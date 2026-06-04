package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/concord-dev/concord/internal/store"
)

// RetrierConfig configures the poll cadence + batch envelope of the
// failed-delivery retrier. The Executor's MaxAttempts cap means a
// single row only flows through the Retrier a bounded number of times.
type RetrierConfig struct {
	// PollInterval is the gap between idle-tick polls. Default 1s —
	// the first-attempt path covers low-latency delivery; the Retrier
	// is for the slow, "receiver is currently broken" cohort.
	PollInterval time.Duration

	// BusyInterval is the shorter gap between ticks when the previous
	// tick processed a full batch. Default 50ms.
	BusyInterval time.Duration

	// ErrorInterval is the sleep after a tick that errored out
	// (claim or DB error). Default 2s.
	ErrorInterval time.Duration

	// BatchSize is the per-tick claim cap. Default 25.
	BatchSize int
}

// RetrierMetrics are the bumps the retrier feeds back. All optional.
type RetrierMetrics struct {
	Tick      func()
	Claimed   func(n int)
	TickError func(err error)
}

// Retrier is the long-running goroutine that re-attempts failed
// webhook_delivery rows whose backoff has elapsed. Construct via
// NewRetrier; start with Run(ctx); cancel ctx to stop.
//
// Safe to run multiple instances against the same Postgres: the
// claim query uses SELECT FOR UPDATE SKIP LOCKED so each replica picks
// rows the others aren't touching.
type Retrier struct {
	store    *store.Store
	executor *Executor
	cfg      RetrierConfig
	metrics  RetrierMetrics
}

// NewRetrier wires the dependencies. Returns an error on nil store or
// executor — both are required.
func NewRetrier(s *store.Store, executor *Executor, cfg RetrierConfig, metrics RetrierMetrics) (*Retrier, error) {
	if s == nil {
		return nil, errors.New("worker: NewRetrier needs a Store")
	}
	if executor == nil {
		return nil, errors.New("worker: NewRetrier needs an Executor")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 1 * time.Second
	}
	if cfg.BusyInterval <= 0 {
		cfg.BusyInterval = 50 * time.Millisecond
	}
	if cfg.ErrorInterval <= 0 {
		cfg.ErrorInterval = 2 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 25
	}
	return &Retrier{
		store:    s,
		executor: executor,
		cfg:      cfg,
		metrics:  metrics,
	}, nil
}

// Run is the main loop. Mirrors the eventbus Dispatcher shape: claim a
// batch under a tx → process each row → commit or roll back. Sleep
// scales with the tick outcome (busy = re-poll fast, error = back off).
func (r *Retrier) Run(ctx context.Context) {
	slog.Info("worker retrier: starting",
		slog.Duration("poll", r.cfg.PollInterval),
		slog.Int("batch", r.cfg.BatchSize),
	)
	defer slog.Info("worker retrier: stopped")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		full, err := r.tick(ctx)
		switch {
		case err != nil:
			if r.metrics.TickError != nil {
				r.metrics.TickError(err)
			}
			slog.Warn("worker retrier: tick failed", slog.String("err", err.Error()))
			sleep(ctx, r.cfg.ErrorInterval)
		case full:
			sleep(ctx, r.cfg.BusyInterval)
		default:
			sleep(ctx, r.cfg.PollInterval)
		}
	}
}

// tick processes one batch. Returns (full, err) — full=true when the
// claim filled BatchSize, so the caller re-polls immediately.
func (r *Retrier) tick(ctx context.Context) (bool, error) {
	if r.metrics.Tick != nil {
		r.metrics.Tick()
	}
	tx, batch, err := r.store.ClaimPendingDeliveries(ctx, r.cfg.BatchSize)
	if err != nil {
		return false, err
	}
	if len(batch) == 0 {
		_ = tx.Rollback(ctx)
		return false, nil
	}
	if r.metrics.Claimed != nil {
		r.metrics.Claimed(len(batch))
	}

	for _, d := range batch {
		body, err := r.rebuildEnvelopeBody(d)
		if err != nil {
			// Marshal of an empty envelope is essentially infallible;
			// log + skip rather than failing the whole tx.
			slog.Error("worker retrier: rebuild envelope failed — skipping",
				slog.String("delivery_id", d.ID.String()),
				slog.String("err", err.Error()))
			continue
		}
		if _, err := r.executor.Attempt(ctx, tx, d.ID, d.EventKind, d.WebhookURL, d.WebhookSecret, body, true); err != nil {
			_ = tx.Rollback(ctx)
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return len(batch) == r.cfg.BatchSize, nil
}

// rebuildEnvelopeBody reconstructs the bytes that go on the wire for a
// retry. The original envelope was stored in the outbox.payload, not
// in webhook_delivery — so we reconstruct from the delivery row's
// fields. The receiver dedupes on event_id, so reconstructing is fine
// as long as the same event_id is preserved.
//
// In a future iteration we could persist the envelope bytes on the
// delivery row to make retries byte-identical to the first attempt
// (some receivers may verify signatures incorporating field order).
// For now, reconstruction is correct because the HMAC is computed
// over the bytes we send, not the original.
func (r *Retrier) rebuildEnvelopeBody(d store.WebhookDelivery) ([]byte, error) {
	// Minimal envelope; matches eventbus.Envelope shape so receivers
	// don't see schema drift between first-attempt and retry.
	env := map[string]any{
		"version":  1,
		"event_id": d.EventID.String(),
		"org_id":   d.OrgID.String(),
		"kind":     d.EventKind,
		// occurred_at is the row's created_at — the closest available
		// proxy when we don't have the original timestamp.
		"occurred_at": d.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	return marshalCompact(env)
}
