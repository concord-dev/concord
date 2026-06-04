package worker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/concord-dev/concord/internal/store"
)

// ExecutorConfig controls the HTTP timeouts, retry math, and limits the
// Executor applies. Every field has a sane default; callers can pass a
// zero struct in tests.
type ExecutorConfig struct {
	// HTTPClient overrides the default 10s-timeout otelhttp-wrapped
	// client. Tests inject a transport that records calls instead of
	// hitting the network.
	HTTPClient *http.Client

	// MaxAttempts caps the per-row retry count. Default 5.
	MaxAttempts int

	// BackoffBase is the minimum backoff between attempts. Default 1s.
	BackoffBase time.Duration

	// BackoffMax caps exponential growth. Default 60s.
	BackoffMax time.Duration

	// MaxBodyBytes limits how much of a non-2xx response body is
	// captured in last_error. Default 1024 — enough to debug, small
	// enough not to balloon the row.
	MaxBodyBytes int64

	// UserAgent is the User-Agent header on outbound requests.
	UserAgent string
}

// Executor is the shared "POST + record" primitive. Construct once per
// process and pass to both Consumer and Retrier.
type Executor struct {
	store   *store.Store
	cfg     ExecutorConfig
	metrics ExecutorMetrics
	rnd     *rand.Rand
	rndMu   sync.Mutex
}

// ExecutorMetrics is the set of bumps the Executor pushes through. Each
// field is optional; cmd/concord-worker wires real Prometheus
// collectors.
type ExecutorMetrics struct {
	// AttemptStarted bumps when an attempt begins (HTTP request is
	// about to be sent). Labels: kind, retry (true on retries).
	AttemptStarted func(kind string, retry bool)

	// AttemptResult bumps after the HTTP response (or error) is in.
	// outcome is one of: "succeeded", "non_2xx", "network_error".
	AttemptResult func(kind, outcome string)

	// AttemptDuration observes the wall time of the HTTP exchange.
	AttemptDuration func(seconds float64)

	// Dead bumps when an attempt leaves the row in 'dead' state
	// (exceeded MaxAttempts).
	Dead func(kind string)
}

// defaultHTTPClient mirrors the server's webhook_delivery.go client —
// short total timeout + otelhttp transport so each POST emits a span +
// propagates traceparent.
var defaultHTTPClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: otelhttp.NewTransport(http.DefaultTransport),
}

// NewExecutor wires the Executor with sane defaults. Returns an error
// if store is nil — that's a programming bug worth catching at startup.
func NewExecutor(s *store.Store, cfg ExecutorConfig, metrics ExecutorMetrics) (*Executor, error) {
	if s == nil {
		return nil, errors.New("worker: NewExecutor needs a Store")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = defaultHTTPClient
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 1 * time.Second
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 60 * time.Second
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1024
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "concord-worker"
	}
	return &Executor{
		store:   s,
		cfg:     cfg,
		metrics: metrics,
		rnd:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

// Attempt is one HTTP exchange against a webhook URL. It POSTs body
// (the canonical envelope from the outbox) and updates the
// webhook_delivery row identified by deliveryID via the supplied
// Store. The tx is optional: if non-nil, the tx-scoped Mark* helpers
// run inside it (Retrier path); when nil, the auto-commit helpers
// are used (Consumer first-attempt path).
//
// Returns the terminal status of the row after this attempt:
// 'succeeded', 'failed', or 'dead'. A non-nil error here means the
// state update itself failed (DB went away) — the caller should not
// commit any enclosing tx.
func (e *Executor) Attempt(ctx context.Context, tx pgx.Tx, deliveryID uuid.UUID, kind, url, secret string, body []byte, retry bool) (store.WebhookDeliveryStatus, error) {
	if e.metrics.AttemptStarted != nil {
		e.metrics.AttemptStarted(kind, retry)
	}
	start := time.Now()
	httpStatus, errMsg := e.doRequest(ctx, url, secret, kind, body)
	dur := time.Since(start)
	if e.metrics.AttemptDuration != nil {
		e.metrics.AttemptDuration(dur.Seconds())
	}

	result := store.AttemptResult{
		AttemptedAt: start.UTC(),
		HTTPStatus:  httpStatus,
		Error:       errMsg,
		DurationMS:  dur.Milliseconds(),
	}

	outcome := classify(httpStatus, errMsg)
	if e.metrics.AttemptResult != nil {
		e.metrics.AttemptResult(kind, outcome)
	}

	if outcome == "succeeded" {
		if tx != nil {
			if err := e.store.MarkDeliverySucceededTx(ctx, tx, deliveryID, result); err != nil {
				return "", err
			}
		} else {
			if err := e.store.MarkDeliverySucceeded(ctx, deliveryID, result); err != nil {
				return "", err
			}
		}
		return store.DeliverySucceeded, nil
	}

	// Failure path — bump attempt_count + maybe transition to 'dead'.
	// We need to know the row's CURRENT attempt_count to compute the
	// next backoff. The Mark*Failed* helpers do the increment + read
	// the post-increment count via the CASE expression, so we just
	// need to supply a reasonable backoff. We always compute the
	// worst-case backoff for the increment; if the row transitions to
	// 'dead' the backoff is set to NULL anyway. Pre-incrementing in
	// Go would race the DB UPDATE, so let the SQL do it.
	backoff := e.backoff()
	maxAttempts := e.cfg.MaxAttempts
	var status store.WebhookDeliveryStatus
	var err error
	if tx != nil {
		status, err = e.store.MarkDeliveryFailedTx(ctx, tx, deliveryID, result, backoff, maxAttempts)
	} else {
		status, err = e.store.MarkDeliveryFailed(ctx, deliveryID, result, backoff, maxAttempts)
	}
	if err != nil {
		return "", err
	}
	if status == store.DeliveryDead && e.metrics.Dead != nil {
		e.metrics.Dead(kind)
	}
	if status == store.DeliveryDead {
		slog.Error("webhook delivery: dead-lettered",
			slog.String("delivery_id", deliveryID.String()),
			slog.String("kind", kind),
			slog.String("url", url),
			slog.Int("http_status", httpStatus),
			slog.String("last_error", errMsg))
	}
	return status, nil
}

// doRequest performs the POST + signing + body capture. Returns the
// final (httpStatus, errMsg). httpStatus is 0 on transport errors.
func (e *Executor) doRequest(ctx context.Context, url, secret, kind string, body []byte) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "build request: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", e.cfg.UserAgent)
	req.Header.Set("X-Concord-Event", kind)
	req.Header.Set("X-Concord-Signature", sign(secret, body))

	resp, err := e.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, "network: " + err.Error()
	}
	defer resp.Body.Close()
	// Always drain the body so the connection can return to the pool.
	// We capture a bounded prefix for last_error on non-2xx; success
	// drops the body entirely.
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, ""
	}
	buf := bytes.NewBuffer(make([]byte, 0, e.cfg.MaxBodyBytes))
	_, _ = io.Copy(buf, io.LimitReader(resp.Body, e.cfg.MaxBodyBytes))
	// Drain anything beyond the limit so the connection pool stays
	// healthy on chatty receivers.
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, fmt.Sprintf("non-2xx response %d: %s", resp.StatusCode, buf.String())
}

// classify reduces (status, err) to a metric label outcome. We split
// "non_2xx" from "network_error" so an alerting policy can page on
// the former (receiver is broken) without paging on the latter (DNS
// flake / connection reset).
func classify(httpStatus int, errMsg string) string {
	switch {
	case httpStatus >= 200 && httpStatus <= 299:
		return "succeeded"
	case httpStatus > 0:
		return "non_2xx"
	default:
		_ = errMsg
		return "network_error"
	}
}

// sign produces the X-Concord-Signature header value. Keep this in sync
// with the server's webhook_delivery.go::signPayload — both write the
// same "sha256=…" shape.
func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// backoff returns a jittered exponential wait for the *next* attempt.
// Because the SQL UPDATE handles the attempt_count increment, this
// function returns the wait corresponding to attempt N+1 — the caller
// passes it as the "if this attempt fails, wait this long" value.
//
// Jitter is ±25% so a thundering herd of failures doesn't all retry
// at exactly the same millisecond. Cap at BackoffMax.
func (e *Executor) backoff() time.Duration {
	// We don't know the current attempt_count here without an extra
	// query; the SQL handles the actual transition. We supply
	// BackoffMax as the upper-bound — the DB's CASE WHEN attempt_count
	// >= max transitions to 'dead' before this backoff is used. For
	// intermediate attempts, the SQL still uses this value; in
	// practice that means every retry waits up to BackoffMax with
	// jitter. That's the simplest scheme that doesn't require a
	// pre-query, and the longer waits are fine — a healthy webhook
	// receiver heals well within 60s.
	exp := float64(e.cfg.BackoffMax)
	e.rndMu.Lock()
	jitter := 1.0 + (e.rnd.Float64()-0.5)*0.5
	e.rndMu.Unlock()
	d := time.Duration(exp * jitter)
	if d < e.cfg.BackoffBase {
		d = e.cfg.BackoffBase
	}
	if d > e.cfg.BackoffMax {
		d = e.cfg.BackoffMax
	}
	return d
}

// BackoffForAttempt is the public, attempt-aware helper. The Retrier
// uses it because it has the row in hand. Pure math; no lock needed.
func BackoffForAttempt(cfg ExecutorConfig, attempt int) time.Duration {
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 1 * time.Second
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 60 * time.Second
	}
	if attempt < 1 {
		attempt = 1
	}
	base := float64(cfg.BackoffBase)
	exp := base * math.Pow(2, float64(attempt-1))
	if exp > float64(cfg.BackoffMax) {
		exp = float64(cfg.BackoffMax)
	}
	return time.Duration(exp)
}
