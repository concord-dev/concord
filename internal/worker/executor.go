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

type ExecutorConfig struct {
	HTTPClient   *http.Client
	MaxAttempts  int
	BackoffBase  time.Duration
	BackoffMax   time.Duration
	MaxBodyBytes int64
	UserAgent    string
}

type Executor struct {
	store    *store.Store
	cfg      ExecutorConfig
	metrics  ExecutorMetrics
	rnd      *rand.Rand
	rndMu    sync.Mutex
	breakers *Breakers
}

func (e *Executor) SetBreakers(b *Breakers) { e.breakers = b }

type ExecutorMetrics struct {
	AttemptStarted  func(kind string, retry bool)
	AttemptResult   func(kind, outcome string)
	AttemptDuration func(seconds float64)
	Dead            func(kind string)
}

var defaultHTTPClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: otelhttp.NewTransport(http.DefaultTransport),
}

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

func (e *Executor) doRequest(ctx context.Context, url, secret, kind string, body []byte) (int, string) {
	var (
		status int
		errMsg string
	)
	bErr := e.breakers.Execute(url, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			errMsg = "build request: " + err.Error()
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", e.cfg.UserAgent)
		req.Header.Set("X-Concord-Event", kind)
		req.Header.Set("X-Concord-Signature", sign(secret, body))

		resp, err := e.cfg.HTTPClient.Do(req)
		if err != nil {
			errMsg = "network: " + err.Error()
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			_, _ = io.Copy(io.Discard, resp.Body)
			status = resp.StatusCode
			return nil
		}
		buf := bytes.NewBuffer(make([]byte, 0, e.cfg.MaxBodyBytes))
		_, _ = io.Copy(buf, io.LimitReader(resp.Body, e.cfg.MaxBodyBytes))
		_, _ = io.Copy(io.Discard, resp.Body)
		status = resp.StatusCode
		errMsg = fmt.Sprintf("non-2xx response %d: %s", resp.StatusCode, buf.String())
		return errors.New("non-2xx")
	})
	if errors.Is(bErr, ErrCircuitOpen) {
		return 0, "circuit_open: receiver is in cooldown after consecutive failures"
	}
	return status, errMsg
}

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

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (e *Executor) backoff() time.Duration {
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
