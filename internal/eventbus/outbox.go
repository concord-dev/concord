package eventbus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Outbox is the persistence surface for the event_outbox table.
type Outbox struct {
	pool *pgxpool.Pool
}

// NewOutbox binds an Outbox to the shared pgxpool.
func NewOutbox(pool *pgxpool.Pool) *Outbox {
	return &Outbox{pool: pool}
}

// EnqueueTx inserts evt into event_outbox under tx. Pass nil tx to use the pool directly.
func (o *Outbox) EnqueueTx(ctx context.Context, tx pgx.Tx, evt Event) (uuid.UUID, error) {
	if err := (&evt).validate(); err != nil {
		return uuid.Nil, err
	}
	payload, err := marshalEnvelope(evt)
	if err != nil {
		return uuid.Nil, fmt.Errorf("eventbus: marshal envelope: %w", err)
	}

	var id uuid.UUID
	var traceparent any
	if evt.Traceparent != "" {
		traceparent = evt.Traceparent
	}
	row := o.row(ctx, tx,
		`INSERT INTO event_outbox
		    (event_id, org_id, kind, payload, traceparent, occurred_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id`,
		evt.EventID, evt.OrgID, evt.Kind, payload, traceparent, evt.OccurredAt,
	)
	if err := row.Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("eventbus: insert outbox: %w", err)
	}
	return id, nil
}

// Enqueue is EnqueueTx against the pool (no transaction).
func (o *Outbox) Enqueue(ctx context.Context, evt Event) (uuid.UUID, error) {
	return o.EnqueueTx(ctx, nil, evt)
}

func (o *Outbox) row(ctx context.Context, tx pgx.Tx, sql string, args ...any) pgx.Row {
	if tx != nil {
		return tx.QueryRow(ctx, sql, args...)
	}
	return o.pool.QueryRow(ctx, sql, args...)
}

type outboxRow struct {
	ID           uuid.UUID
	EventID      uuid.UUID
	OrgID        uuid.UUID
	Kind         string
	Payload      []byte
	Traceparent  *string
	OccurredAt   time.Time
	AttemptCount int
}

func (o *Outbox) claimBatch(ctx context.Context, limit int, maxAttempts int) (pgx.Tx, []outboxRow, error) {
	tx, err := o.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("eventbus: begin claim: %w", err)
	}
	rows, err := tx.Query(ctx,
		`SELECT id, event_id, org_id, kind, payload, traceparent, occurred_at, attempt_count
		 FROM event_outbox
		 WHERE published_at IS NULL
		   AND abandoned_at IS NULL
		   AND attempt_count < $1
		   AND next_attempt_at <= now()
		 ORDER BY next_attempt_at, created_at
		 LIMIT $2
		 FOR UPDATE SKIP LOCKED`,
		maxAttempts, limit,
	)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, nil, fmt.Errorf("eventbus: claim batch: %w", err)
	}
	defer rows.Close()

	var batch []outboxRow
	for rows.Next() {
		var r outboxRow
		if err := rows.Scan(&r.ID, &r.EventID, &r.OrgID, &r.Kind, &r.Payload,
			&r.Traceparent, &r.OccurredAt, &r.AttemptCount); err != nil {
			_ = tx.Rollback(ctx)
			return nil, nil, fmt.Errorf("eventbus: scan claim: %w", err)
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		_ = tx.Rollback(ctx)
		return nil, nil, fmt.Errorf("eventbus: iterate claim: %w", err)
	}
	return tx, batch, nil
}

func (o *Outbox) markPublished(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx,
		`UPDATE event_outbox
		 SET published_at = now(),
		     last_error = NULL
		 WHERE id = $1 AND published_at IS NULL`,
		id)
	return err
}

func (o *Outbox) markFailed(ctx context.Context, tx pgx.Tx, id uuid.UUID, errStr string, backoff time.Duration) error {
	_, err := tx.Exec(ctx,
		`UPDATE event_outbox
		 SET attempt_count = attempt_count + 1,
		     last_error = $2,
		     next_attempt_at = now() + ($3::bigint * interval '1 microsecond')
		 WHERE id = $1`,
		id, errStr, backoff.Microseconds())
	return err
}

// LagSeconds returns the age (s) of the oldest unpublished, non-dead row, or 0 if none.
func (o *Outbox) LagSeconds(ctx context.Context, maxAttempts int) (float64, error) {
	var secs *float64
	err := o.pool.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (now() - MIN(created_at)))
		 FROM event_outbox
		 WHERE published_at IS NULL AND abandoned_at IS NULL AND attempt_count < $1`,
		maxAttempts,
	).Scan(&secs)
	if err != nil {
		return 0, err
	}
	if secs == nil {
		return 0, nil
	}
	return *secs, nil
}

// CleanupPublished deletes published rows older than retain; returns rows removed.
func (o *Outbox) CleanupPublished(ctx context.Context, retain time.Duration) (int64, error) {
	tag, err := o.pool.Exec(ctx,
		`DELETE FROM event_outbox
		 WHERE published_at IS NOT NULL
		   AND published_at < now() - ($1::bigint * interval '1 microsecond')`,
		retain.Microseconds())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DispatcherConfig tunes the Dispatcher loop. Zero fields fall back to defaults.
type DispatcherConfig struct {
	PollInterval    time.Duration
	BusyInterval    time.Duration
	ErrorInterval   time.Duration
	BatchSize       int
	MaxAttempts     int
	BackoffBase     time.Duration
	BackoffMax      time.Duration
	CleanupInterval time.Duration
	CleanupRetain   time.Duration
}

// Dispatcher polls the outbox and ships rows to a Publisher.
type Dispatcher struct {
	outbox    *Outbox
	publisher Publisher
	cfg       DispatcherConfig
	metrics   DispatcherMetrics
	rnd       *rand.Rand
	rndMu     sync.Mutex
}

// DispatcherMetrics exposes optional metric callbacks; nil fields are no-ops.
type DispatcherMetrics struct {
	Enqueued    func(kind string)
	Published   func(kind string)
	Failed      func(kind string)
	Dead        func(kind string)
	PublishTime func(seconds float64)
	Lag         func(seconds float64)
	Cleaned     func(deleted int64)
	TickError   func(stage string, err error)
}

// NewDispatcher fills defaults and returns a ready-to-run Dispatcher.
func NewDispatcher(outbox *Outbox, publisher Publisher, cfg DispatcherConfig, metrics DispatcherMetrics) (*Dispatcher, error) {
	if outbox == nil {
		return nil, errors.New("eventbus: NewDispatcher needs an Outbox")
	}
	if publisher == nil {
		return nil, errors.New("eventbus: NewDispatcher needs a Publisher")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 200 * time.Millisecond
	}
	if cfg.BusyInterval <= 0 {
		cfg.BusyInterval = 1 * time.Millisecond
	}
	if cfg.ErrorInterval <= 0 {
		cfg.ErrorInterval = 1 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 20
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 1 * time.Second
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 5 * time.Minute
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 1 * time.Hour
	}
	if cfg.CleanupRetain <= 0 {
		cfg.CleanupRetain = 7 * 24 * time.Hour
	}

	return &Dispatcher{
		outbox:    outbox,
		publisher: publisher,
		cfg:       cfg,
		metrics:   metrics,
		rnd:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

// Run is the main loop. Blocks until ctx is cancelled.
func (d *Dispatcher) Run(ctx context.Context) {
	slog.Info("event dispatcher: starting",
		slog.Duration("poll", d.cfg.PollInterval),
		slog.Int("batch", d.cfg.BatchSize),
		slog.Int("max_attempts", d.cfg.MaxAttempts),
	)
	go d.runCleanup(ctx)
	go d.runLagPoller(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("event dispatcher: stopping")
			return
		default:
		}

		full, err := d.tick(ctx)
		switch {
		case err != nil:
			if d.metrics.TickError != nil {
				d.metrics.TickError("tick", err)
			}
			slog.Warn("event dispatcher: tick failed", slog.String("err", err.Error()))
			sleep(ctx, d.cfg.ErrorInterval)
		case full:
			sleep(ctx, d.cfg.BusyInterval)
		default:
			sleep(ctx, d.cfg.PollInterval)
		}
	}
}

func (d *Dispatcher) tick(ctx context.Context) (bool, error) {
	tx, batch, err := d.outbox.claimBatch(ctx, d.cfg.BatchSize, d.cfg.MaxAttempts)
	if err != nil {
		return false, err
	}
	if len(batch) == 0 {
		_ = tx.Rollback(ctx)
		return false, nil
	}

	for _, r := range batch {
		if err := d.dispatchOne(ctx, tx, r); err != nil {
			_ = tx.Rollback(ctx)
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("eventbus: commit batch: %w", err)
	}
	return len(batch) == d.cfg.BatchSize, nil
}

func (d *Dispatcher) dispatchOne(ctx context.Context, tx pgx.Tx, r outboxRow) error {
	headers := map[string]string{
		"event-id":   r.EventID.String(),
		"event-kind": r.Kind,
		"org-id":     r.OrgID.String(),
	}
	if r.Traceparent != nil && *r.Traceparent != "" {
		headers["traceparent"] = *r.Traceparent
	}

	start := time.Now()
	pubCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := d.publisher.Publish(pubCtx, r.OrgID.String(), r.Payload, headers)
	cancel()
	if d.metrics.PublishTime != nil {
		d.metrics.PublishTime(time.Since(start).Seconds())
	}

	if err == nil {
		if err := d.outbox.markPublished(ctx, tx, r.ID); err != nil {
			return fmt.Errorf("markPublished id=%s: %w", r.ID, err)
		}
		if d.metrics.Published != nil {
			d.metrics.Published(r.Kind)
		}
		return nil
	}

	backoff := d.backoff(r.AttemptCount + 1)
	if mfErr := d.outbox.markFailed(ctx, tx, r.ID, err.Error(), backoff); mfErr != nil {
		return fmt.Errorf("markFailed id=%s (publish err=%v): %w", r.ID, err, mfErr)
	}
	if r.AttemptCount+1 >= d.cfg.MaxAttempts {
		if d.metrics.Dead != nil {
			d.metrics.Dead(r.Kind)
		}
		slog.Error("event dispatcher: row reached max attempts (dead-letter)",
			slog.String("id", r.ID.String()),
			slog.String("event_id", r.EventID.String()),
			slog.String("kind", r.Kind),
			slog.Int("attempts", r.AttemptCount+1),
			slog.String("last_error", err.Error()),
		)
	} else if d.metrics.Failed != nil {
		d.metrics.Failed(r.Kind)
	}
	return nil
}

func (d *Dispatcher) backoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	base := float64(d.cfg.BackoffBase)
	exp := base * math.Pow(2, float64(n-1))
	if exp > float64(d.cfg.BackoffMax) {
		exp = float64(d.cfg.BackoffMax)
	}
	d.rndMu.Lock()
	jitter := 1.0 + (d.rnd.Float64()-0.5)*0.5
	d.rndMu.Unlock()
	return time.Duration(exp * jitter)
}

func (d *Dispatcher) runCleanup(ctx context.Context) {
	t := time.NewTicker(d.cfg.CleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := d.outbox.CleanupPublished(ctx, d.cfg.CleanupRetain)
			if err != nil {
				if d.metrics.TickError != nil {
					d.metrics.TickError("cleanup", err)
				}
				slog.Warn("event dispatcher: cleanup failed", slog.String("err", err.Error()))
				continue
			}
			if n > 0 {
				slog.Info("event dispatcher: cleaned published rows", slog.Int64("deleted", n))
			}
			if d.metrics.Cleaned != nil {
				d.metrics.Cleaned(n)
			}
		}
	}
}

func (d *Dispatcher) runLagPoller(ctx context.Context) {
	if d.metrics.Lag == nil {
		return
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			secs, err := d.outbox.LagSeconds(ctx, d.cfg.MaxAttempts)
			if err != nil {
				if d.metrics.TickError != nil {
					d.metrics.TickError("lag", err)
				}
				continue
			}
			d.metrics.Lag(secs)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
