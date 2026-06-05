package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/concord-dev/concord/internal/store"
)

// RetrierConfig tunes the failed-delivery poll loop. Zero fields fall back to defaults.
type RetrierConfig struct {
	PollInterval  time.Duration
	BusyInterval  time.Duration
	ErrorInterval time.Duration
	BatchSize     int
}

// RetrierMetrics is the set of optional bumps the Retrier pushes.
type RetrierMetrics struct {
	Tick      func()
	Claimed   func(n int)
	TickError func(err error)
}

// Retrier polls webhook_delivery for failed rows whose backoff elapsed and re-runs Attempt.
type Retrier struct {
	store    *store.Store
	executor *Executor
	cfg      RetrierConfig
	metrics  RetrierMetrics
}

// NewRetrier returns a Retrier with defaults applied. store + executor required.
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

// Run is the main loop. Blocks until ctx is cancelled.
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

// rebuildEnvelopeBody reconstructs the wire body for a retry. event_id stays
// stable; receivers dedupe on it, so byte-identity with the first attempt
// isn't required.
func (r *Retrier) rebuildEnvelopeBody(d store.WebhookDelivery) ([]byte, error) {
	env := map[string]any{
		"version":     1,
		"event_id":    d.EventID.String(),
		"org_id":      d.OrgID.String(),
		"kind":        d.EventKind,
		"occurred_at": d.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	return marshalCompact(env)
}
