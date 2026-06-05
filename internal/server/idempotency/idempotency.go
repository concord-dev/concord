// Package idempotency is the Redis-backed Idempotency-Key middleware. It
// gives mutating endpoints (POST /v1/orgs/{slug}/runs, …) the same
// "client retries are safe" guarantee Stripe and GitHub publish: a
// caller that re-sends the same request with the same Idempotency-Key
// header gets the cached response instead of executing the handler
// twice. Cluster-safe — the store is Redis, so multiple replicas of
// concord-server share one keyspace.
//
// Wire shape (matches the industry convention):
//
//   Idempotency-Key: <client-generated UUID v4, max 255 chars>
//
// Lifecycle:
//
//   1. Middleware computes a request fingerprint from method + path +
//      sha256(body) — a body-bounded version that won't hash a 25MB
//      run submission. Body is buffered in memory so the downstream
//      handler still sees it.
//
//   2. SETNX claims `idem:<scope>:<key>` with a "pending" sentinel and
//      a 24h TTL. If the SETNX succeeds the handler runs; the
//      response (status + body + Content-Type) is captured via a
//      buffering ResponseWriter and stored under the same key for the
//      remaining TTL.
//
//   3. If the SETNX fails the existing value is loaded:
//        - "pending"          → 409 Conflict (request still in flight;
//                               client should retry shortly).
//        - cached response    → fingerprint mismatch → 422
//                              Unprocessable Entity (caller bug:
//                              same key, different request).
//                              fingerprint match → return cached.
//
// Idempotency is OPT-IN per caller — handlers that should be guarded
// pass through this middleware; clients that don't send the header
// skip the dedupe entirely and pay only one Redis Exists check (which
// short-circuits when the header is absent).
//
// Failure modes: a Redis outage degrades the middleware to pass-through
// (the handler runs as if Idempotency-Key wasn't present), with a
// metric bumped so an operator notices. The alternative — fail-closed
// — would 503 every mutating request during a Redis blip, which is a
// strictly worse trade than risking a duplicate.
package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/concord-dev/concord/internal/server/httpx"
)

// MaxBodyBytes caps how much of the request body the fingerprint
// hashes and the dedupe machinery buffers. 1MiB is plenty for JSON
// mutations and bounds memory under load. Run submissions go to a
// different limit (25MB) — those endpoints either skip idempotency
// or accept the trade-off that the dedupe window only protects up
// to MaxBodyBytes of body content.
const MaxBodyBytes = 1 << 20 // 1 MiB

// CachedTTL is how long a recorded response stays in Redis. 24h matches
// the Stripe / GitHub default — long enough that a flaky network with
// minute-scale outages can still reconcile, short enough that a stale
// key from "last week" can't accidentally short-circuit a fresh
// request that happens to reuse a UUID.
const CachedTTL = 24 * time.Hour

// PendingTTL is the TTL on the SETNX "pending" sentinel. Shorter than
// CachedTTL because a pending record means a handler is in flight; if
// the process crashed mid-handler the row should expire so the next
// retry can proceed instead of being permanently locked behind a
// stale lock. 5 minutes covers any reasonable handler timeout.
const PendingTTL = 5 * time.Minute

// scopeOrgSubmissions is the keyspace prefix for org-scoped mutations.
// We namespace per org so a key collision between tenants is impossible.
const scopeOrgSubmissions = "idem:org"

// Config is what cmd/server passes to construct the middleware.
type Config struct {
	// Redis is the shared client. nil disables idempotency entirely —
	// the middleware becomes a no-op pass-through, which is the
	// dev/single-pod default.
	Redis *redis.Client

	// OrgIDFn extracts an org-scoping value (typically the org id or
	// slug from the URL) so per-tenant key collisions can't happen.
	// Returns ("", false) when the request is unscoped — in that case
	// the middleware uses a global "idem:unscoped:" namespace.
	OrgIDFn func(r *http.Request) (string, bool)

	// OnRedisError is invoked when a Redis call fails and the
	// middleware degrades to pass-through. Wire to a Prometheus
	// counter in cmd/server.
	OnRedisError func(err error)

	// OnHit is bumped when a cached response was served (the
	// happy-path dedupe outcome).
	OnHit func()

	// OnMismatch is bumped when a key was reused with a different
	// request fingerprint — a caller-side bug.
	OnMismatch func()

	// OnPending is bumped when a key is reused while the original
	// request is still in flight (returns 409).
	OnPending func()
}

// Middleware constructs the http.Handler middleware from cfg.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("Idempotency-Key")
			if key == "" || cfg.Redis == nil {
				next.ServeHTTP(w, r)
				return
			}
			if len(key) > 255 {
				httpx.Error(w, http.StatusBadRequest, "Idempotency-Key must be at most 255 chars")
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "reading body: "+err.Error())
				return
			}
			if len(body) > MaxBodyBytes {
				httpx.Error(w, http.StatusRequestEntityTooLarge,
					"body exceeds 1MiB; idempotency cannot be applied")
				return
			}
			// Restore the body for the downstream handler.
			r.Body = io.NopCloser(bytes.NewReader(body))

			fingerprint := requestFingerprint(r, body)
			scope := keyScope(cfg, r)
			fullKey := scope + ":" + key

			ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			defer cancel()

			// SETNX the pending sentinel. JSON-encoded so the cached
			// response shape (also JSON) can be distinguished trivially.
			pendingJSON, _ := json.Marshal(record{Status: 0, Fingerprint: fingerprint})
			ok, err := cfg.Redis.SetNX(ctx, fullKey, pendingJSON, PendingTTL).Result()
			if err != nil {
				if cfg.OnRedisError != nil {
					cfg.OnRedisError(err)
				}
				// Degrade to pass-through; the original behaviour
				// without this middleware. The cost is a possible
				// duplicate during a Redis outage — strictly preferred
				// over 503'ing every POST.
				next.ServeHTTP(w, r)
				return
			}
			if !ok {
				// Slot already taken. Decide based on the stored value.
				raw, err := cfg.Redis.Get(ctx, fullKey).Result()
				if err != nil {
					if cfg.OnRedisError != nil {
						cfg.OnRedisError(err)
					}
					next.ServeHTTP(w, r)
					return
				}
				var prev record
				if jerr := json.Unmarshal([]byte(raw), &prev); jerr != nil {
					// Corrupted cache row — fail open with a 500 so
					// the bug surfaces. Should never happen because
					// only this middleware writes the namespace.
					httpx.Error(w, http.StatusInternalServerError,
						"idempotency cache corrupt")
					return
				}
				if prev.Status == 0 {
					if cfg.OnPending != nil {
						cfg.OnPending()
					}
					w.Header().Set("Retry-After", "1")
					httpx.Error(w, http.StatusConflict,
						"another request with this Idempotency-Key is still in flight")
					return
				}
				if prev.Fingerprint != fingerprint {
					if cfg.OnMismatch != nil {
						cfg.OnMismatch()
					}
					httpx.Error(w, http.StatusUnprocessableEntity,
						"Idempotency-Key was previously used for a different request")
					return
				}
				// Replay the cached response.
				if cfg.OnHit != nil {
					cfg.OnHit()
				}
				replayCached(w, prev)
				return
			}

			// We hold the slot. Run the handler with a buffering
			// writer so we can persist the response.
			cw := newCapturingWriter(w)
			next.ServeHTTP(cw, r)

			// Cap response capture at MaxBodyBytes — protects Redis
			// memory if a handler ever streams a huge body.
			body = cw.body.Bytes()
			if len(body) > MaxBodyBytes {
				body = body[:MaxBodyBytes]
			}
			rec := record{
				Status:      cw.status,
				ContentType: cw.contentType(),
				Body:        body,
				Fingerprint: fingerprint,
			}
			storeCtx, storeCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer storeCancel()
			payload, _ := json.Marshal(rec)
			if err := cfg.Redis.Set(storeCtx, fullKey, payload, CachedTTL).Err(); err != nil {
				if cfg.OnRedisError != nil {
					cfg.OnRedisError(err)
				}
				// Already responded to the client; nothing to do but
				// log the loss-of-replay risk. We deliberately do NOT
				// roll back the response — the side effects already
				// happened.
			}
		})
	}
}

// record is the on-the-wire shape we store in Redis. Status=0 means
// "pending" — the slot is claimed but no response is recorded yet.
type record struct {
	Status      int    `json:"s"`
	ContentType string `json:"ct,omitempty"`
	Body        []byte `json:"b,omitempty"`
	Fingerprint string `json:"fp"`
}

// requestFingerprint binds method + path + body together so a caller
// reusing the same Idempotency-Key for a different request gets a 422
// rather than the cached response from the first.
func requestFingerprint(r *http.Request, body []byte) string {
	h := sha256.New()
	h.Write([]byte(r.Method))
	h.Write([]byte{0})
	h.Write([]byte(r.URL.Path))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// keyScope returns the "idem:<scope>" prefix the SETNX uses, so cache
// keys cannot collide across tenants.
func keyScope(cfg Config, r *http.Request) string {
	if cfg.OrgIDFn != nil {
		if scope, ok := cfg.OrgIDFn(r); ok {
			return scopeOrgSubmissions + ":" + scope
		}
	}
	return "idem:unscoped"
}

// replayCached writes the previously captured response to w. Honours
// the originally observed Content-Type so consumers that switch on
// it see the same shape.
func replayCached(w http.ResponseWriter, rec record) {
	if rec.ContentType != "" {
		w.Header().Set("Content-Type", rec.ContentType)
	}
	w.Header().Set("Idempotency-Replay", "true")
	w.WriteHeader(rec.Status)
	if len(rec.Body) > 0 {
		_, _ = w.Write(rec.Body)
	}
}

// capturingWriter is the ResponseWriter wrapper that records the
// handler's response into a buffer so it can be persisted to Redis.
type capturingWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func newCapturingWriter(w http.ResponseWriter) *capturingWriter {
	return &capturingWriter{ResponseWriter: w, status: http.StatusOK}
}

func (c *capturingWriter) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *capturingWriter) Write(p []byte) (int, error) {
	// Mirror to both the downstream client and our buffer so the
	// client never sees a delay from capture.
	c.body.Write(p)
	return c.ResponseWriter.Write(p)
}

func (c *capturingWriter) contentType() string {
	return c.Header().Get("Content-Type")
}

// ErrUnconfigured is returned by Open when neither Redis nor a
// fallback is wired and the caller insists on an enforcing middleware.
// Today Middleware degrades gracefully so this is unused; reserved
// for a future "must enforce" flag.
var ErrUnconfigured = errors.New("idempotency: no backend configured")
