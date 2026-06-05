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

const MaxBodyBytes = 1 << 20 // 1 MiB

const CachedTTL = 24 * time.Hour

const PendingTTL = 5 * time.Minute

const scopeOrgSubmissions = "idem:org"

type Config struct {
	Redis *redis.Client

	OrgIDFn func(r *http.Request) (string, bool)

	OnRedisError func(err error)

	OnHit func()

	OnMismatch func()

	OnPending func()
}

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
			r.Body = io.NopCloser(bytes.NewReader(body))

			fingerprint := requestFingerprint(r, body)
			scope := keyScope(cfg, r)
			fullKey := scope + ":" + key

			ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			defer cancel()

			pendingJSON, _ := json.Marshal(record{Status: 0, Fingerprint: fingerprint})
			ok, err := cfg.Redis.SetNX(ctx, fullKey, pendingJSON, PendingTTL).Result()
			if err != nil {
				if cfg.OnRedisError != nil {
					cfg.OnRedisError(err)
				}
				next.ServeHTTP(w, r)
				return
			}
			if !ok {
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
				if cfg.OnHit != nil {
					cfg.OnHit()
				}
				replayCached(w, prev)
				return
			}

			cw := newCapturingWriter(w)
			next.ServeHTTP(cw, r)

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
			}
		})
	}
}

type record struct {
	Status      int    `json:"s"`
	ContentType string `json:"ct,omitempty"`
	Body        []byte `json:"b,omitempty"`
	Fingerprint string `json:"fp"`
}

func requestFingerprint(r *http.Request, body []byte) string {
	h := sha256.New()
	h.Write([]byte(r.Method))
	h.Write([]byte{0})
	h.Write([]byte(r.URL.Path))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func keyScope(cfg Config, r *http.Request) string {
	if cfg.OrgIDFn != nil {
		if scope, ok := cfg.OrgIDFn(r); ok {
			return scopeOrgSubmissions + ":" + scope
		}
	}
	return "idem:unscoped"
}

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
	c.body.Write(p)
	return c.ResponseWriter.Write(p)
}

func (c *capturingWriter) contentType() string {
	return c.Header().Get("Content-Type")
}

var ErrUnconfigured = errors.New("idempotency: no backend configured")
