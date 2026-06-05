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

// Outbox is the persistence surface for the event_outbox table. The
// Enqueue method is the only path handlers should use to ship a domain
// event; never write to event_outbox by hand.
//
// The dispatcher reads from the same table via the Pool — it does not
// share state with Outbox beyond the schema.
type Outbox struct {
	pool *pgxpool.Pool
}

// NewOutbox binds an Outbox to the shared pgxpool. The pool must already
// be open; this constructor does no I/O.
func NewOutbox(pool *pgxpool.Pool) *Outbox {
	return &Outbox{pool: pool}
}

// EnqueueTx inserts evt into event_outbox using the supplied pgx.Tx.
// Callers SHOULD pass the same tx that performs the underlying state
// change so the event and the state commit together (transactional
// outbox pattern). If tx is nil, the call falls back to the Outbox's
// pool — useful for "fire and forget" events that don't tie to a
// concurrent state change.
//
// Returns the inserted row's id and any DB error. Missing fields on evt
// are filled in (EventID defaults to a fresh UUID, OccurredAt to now)
// before persisting.
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

// Enqueue is the convenience wrapper that uses the Outbox's pool
// directly (no transaction). Use this when there is no concurrent
// state change to bind to — e.g. "user manually triggered a webhook
// test". For anything that mutates persistent state, prefer EnqueueTx.
func (o *Outbox) Enqueue(ctx context.Context, evt Event) (uuid.UUID, error) {
	return o.EnqueueTx(ctx, nil, evt)
}

// row picks the right executor depending on whether tx is non-nil.
// Centralised so Enqueue / EnqueueTx don't duplicate the conditional.
func (o *Outbox) row(ctx context.Context, tx pgx.Tx, sql string, args ...any) pgx.Row {
	if tx != nil {
		return tx.QueryRow(ctx, sql, args...)
	}
	return o.pool.QueryRow(ctx, sql, args...)
}

// outboxRow is the in-memory shape of one event_outbox row at claim time.
// Internal — the dispatcher uses it to drive Publisher calls.
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

// claimBatch grabs up to limit pending rows for processing using
// SELECT FOR UPDATE SKIP LOCKED. The SKIP LOCKED is what lets multiple
// dispatcher replicas cooperate without coordination: each replica picks
// rows the others aren't touching, so the work is sharded automatically.
//
// The returned tx must be committed (success) or rolled back (failure
// path you don't want to commit) by the caller.
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

// markPublished records a successful Kafka publish under the same tx as
// the claim. Idempotent in the dispatcher (rows are claim-locked) — but
// we still guard with WHERE published_at IS NULL so a buggy double-commit
// can't undo the published_at stamp.
func (o *Outbox) markPublished(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx,
		`UPDATE event_outbox
		 SET published_at = now(),
		     last_error = NULL
		 WHERE id = $1 AND published_at IS NULL`,
		id)
	return err
}

// markFailed bumps attempt_count, stamps last_error, and schedules the
// next attempt at now() + backoff. Runs under the claim tx so a crash
// between Publish and this UPDATE leaves the row eligible for re-claim
// without an artificial backoff delay (next_attempt_at stays where it was).
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

// LagSeconds returns the age of the oldest unpublished, non-dead row in
// seconds. Wired to a Prometheus gauge so an alert can fire on a stalled
// dispatcher or a Kafka outage. Returns 0 when there is nothing pending.
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

// CleanupPublished deletes rows older than retain from the table. Returns
// the number of rows removed. Operators wire this to a periodic sweeper;
// keeping a few days of published rows is useful for debugging and for
// out-of-band consumer replays.
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

// DispatcherConfig configures a Dispatcher. Every field has a sane
// default applied by NewDispatcher; a caller can pass an empty struct.
type DispatcherConfig struct {
	// PollInterval is how often the dispatcher wakes to check for new
	// pending rows when the previous tick was idle. Default 200ms — low
	// enough to feel real-time, high enough that an idle cluster
	// doesn't burn CPU on empty queries.
	PollInterval time.Duration

	// BusyInterval is the (shorter) sleep between ticks when the
	// previous tick processed a full batch — there's probably more
	// work waiting, so re-poll quickly. Default 1ms.
	BusyInterval time.Duration

	// ErrorInterval is the sleep when the last tick errored out (DB
	// down, Kafka down, …). Default 1s — slow enough not to spam logs
	// during a sustained outage, fast enough to recover quickly.
	ErrorInterval time.Duration

	// BatchSize is the per-tick claim limit. Default 50. Larger
	// improves throughput on busy clusters but means a slow Kafka stalls
	// more rows behind a long batch.
	BatchSize int

	// MaxAttempts caps the retry count. Once a row hits this many
	// attempts it stays unpublished — Phase 4 will add operator-facing
	// inspect/replay. Default 20 (= ~30 minutes of backoff before giving
	// up, see backoff()).
	MaxAttempts int

	// BackoffBase is the minimum backoff between attempts. Default 1s.
	BackoffBase time.Duration

	// BackoffMax caps the exponential growth. Default 5min — long
	// enough that a slow broker doesn't get hammered, short enough that
	// recovery doesn't take all day.
	BackoffMax time.Duration

	// CleanupInterval is how often to run the published-row delete
	// sweep. Default 1h.
	CleanupInterval time.Duration

	// CleanupRetain is how long to keep already-published rows around.
	// Default 7 days — enough for forensic SQL queries on recent activity.
	CleanupRetain time.Duration
}

// Dispatcher is the long-running goroutine that ships outbox rows to
// Kafka. Construct via NewDispatcher; start with Run(ctx); cancel ctx to
// stop. Run blocks until ctx is done.
//
// Safe to run multiple instances against the same Postgres + Kafka: the
// SELECT FOR UPDATE SKIP LOCKED in claimBatch guarantees rows aren't
// double-processed across replicas.
type Dispatcher struct {
	outbox    *Outbox
	publisher Publisher
	cfg       DispatcherConfig
	metrics   DispatcherMetrics
	rnd       *rand.Rand
	rndMu     sync.Mutex
}

// DispatcherMetrics is the set of counters/gauges the dispatcher
// pumps. Each field may be nil — the dispatcher no-ops on nil so tests
// can construct without wiring metrics. cmd/server passes the real
// Prometheus collectors.
type DispatcherMetrics struct {
	Enqueued    func(kind string)        // optional — bumped by Enqueue callers, not by the dispatcher
	Published   func(kind string)        // success
	Failed      func(kind string)        // publish error, will retry
	Dead        func(kind string)        // exceeded MaxAttempts
	PublishTime func(seconds float64)    // produce wall-time histogram
	Lag         func(seconds float64)    // refreshed every poll loop
	Cleaned     func(deleted int64)      // periodic cleanup result
	TickError   func(stage string, err error) // observability for unexpected DB / kafka errors
}

// NewDispatcher fills defaults onto cfg and returns a ready-to-run
// Dispatcher. The supplied publisher is invoked once per row; nil
// publisher is rejected at construction time.
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
		// Seed with a low-quality source — we just need jitter, not
		// crypto. Per-dispatcher state to avoid the global rand mutex
		// contention under load.
		rnd: rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

// Run is the main loop. Blocks until ctx is cancelled. The loop is:
//
//  1. Claim up to BatchSize rows (SELECT FOR UPDATE SKIP LOCKED).
//  2. For each row: marshal + Publish + (markPublished | markFailed).
//  3. Commit the claim tx.
//  4. Sleep: BusyInterval if the batch was full (more work likely
//     waiting), ErrorInterval if the tick failed, PollInterval
//     otherwise.
//
// Cleanup runs on its own ticker so a slow DELETE doesn't stall the
// publish loop.
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

// tick processes one batch. Returns (full, err) — full=true when the
// claim filled BatchSize (likely more work waiting), so the caller
// re-polls immediately.
func (d *Dispatcher) tick(ctx context.Context) (bool, error) {
	tx, batch, err := d.outbox.claimBatch(ctx, d.cfg.BatchSize, d.cfg.MaxAttempts)
	if err != nil {
		return false, err
	}
	if len(batch) == 0 {
		// Empty claim — commit to release the empty snapshot tx
		// promptly, then idle.
		_ = tx.Rollback(ctx)
		return false, nil
	}

	for _, r := range batch {
		if err := d.dispatchOne(ctx, tx, r); err != nil {
			// A markPublished / markFailed UPDATE error is a structural
			// problem (the DB went away). Abort the whole tx — any rows
			// we've already touched roll back. The next tick re-claims.
			_ = tx.Rollback(ctx)
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("eventbus: commit batch: %w", err)
	}
	return len(batch) == d.cfg.BatchSize, nil
}

// dispatchOne ships one row. Three outcomes:
//
//   - Publish succeeds → markPublished.
//   - Publish fails, attempt_count+1 < MaxAttempts → markFailed (retry later).
//   - Publish fails, attempt_count+1 >= MaxAttempts → markFailed (dead).
//
// The "dead" classification is implicit — the claim query filters on
// attempt_count < MaxAttempts so a dead row simply never gets re-claimed.
// We still increment attempt_count + last_error so an operator can read
// it later.
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

// backoff returns the wait time before the n-th attempt. Jittered
// exponential: base * 2^(n-1) with ±25% jitter, capped at BackoffMax.
// Jitter avoids a thundering herd when many rows share the same failure
// window (e.g. Kafka 30s outage → every row fires at exactly t+1s without it).
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
	jitter := 1.0 + (d.rnd.Float64()-0.5)*0.5 // ±25%
	d.rndMu.Unlock()
	return time.Duration(exp * jitter)
}

// runCleanup is the periodic published-row delete sweep. Runs in its
// own goroutine so a slow DELETE never stalls the publish loop.
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

// runLagPoller refreshes the lag gauge every 10s. Cheap MIN() against
// the partial index; bounded so an alert can fire on "oldest unpublished
// row is > 60s old".
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

// sleep is context.Done-aware sleep so cancellation doesn't have to wait
// out the full duration. The select pattern is the standard Go shape;
// keeping it in one helper centralises the cancellation discipline.
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
