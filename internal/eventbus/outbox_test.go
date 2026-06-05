package eventbus_test

import (
	"context"
	"errors"
	"fmt"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/eventbus"
	"github.com/concord-dev/concord/internal/store"
)


const defaultTestDSN = "postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable"

// openIsolatedPool creates a fresh per-test database, runs migrations,
// and returns the underlying pgxpool. The eventbus tests need raw pool
// access (the Outbox is pool-bound) so we don't go through Store like
// the store_test package does — but we still use a unique DB so we
// don't race the shared concord database.
func openIsolatedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	baseDSN := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if baseDSN == "" {
		baseDSN = defaultTestDSN
	}
	u, err := url.Parse(baseDSN)
	require.NoError(t, err, "parsing CONCORD_TEST_DATABASE_URL")
	u.Path = "/postgres"
	ctlDSN := u.String()

	dbName := "concord_eb_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctl, err := pgx.Connect(ctx, ctlDSN)
	if err != nil {
		t.Skipf("skipping: Postgres control DB not reachable: %v", err)
	}
	if _, err := ctl.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %q`, dbName)); err != nil {
		_ = ctl.Close(ctx)
		t.Fatalf("creating test DB: %v", err)
	}
	_ = ctl.Close(ctx)

	u.Path = "/" + dbName
	s, err := store.Open(ctx, u.String(), store.PoolOptions{MaxConns: 8, MinConns: 1})
	require.NoError(t, err)
	require.NoError(t, s.Migrate(ctx))

	t.Cleanup(func() {
		s.Close()
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		dropCtl, err := pgx.Connect(dropCtx, ctlDSN)
		if err != nil {
			t.Logf("cleanup: %v", err)
			return
		}
		defer dropCtl.Close(dropCtx)
		_, _ = dropCtl.Exec(dropCtx,
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
			dbName)
		_, _ = dropCtl.Exec(dropCtx, fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, dbName))
	})

	return s.Pool()
}

// seedOrg inserts a minimal organization so event_outbox's FK is satisfied.
func seedOrg(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO organization (name, slug) VALUES ($1, $2) RETURNING id`,
		"test org "+uuid.NewString()[:8],
		"test-"+uuid.NewString()[:8],
	).Scan(&id)
	require.NoError(t, err)
	return id
}


func TestOutbox_EnqueuePersistsCanonicalRow(t *testing.T) {
	pool := openIsolatedPool(t)
	orgID := seedOrg(t, pool)
	outbox := eventbus.NewOutbox(pool)

	eventID := uuid.New()
	occurred := time.Now().UTC().Truncate(time.Microsecond) // pg's timestamptz precision
	id, err := outbox.Enqueue(context.Background(), eventbus.Event{
		EventID:     eventID,
		OrgID:       orgID,
		Kind:        "run.completed",
		OccurredAt:  occurred,
		Data:        map[string]any{"run_id": "abc"},
		Traceparent: "00-deadbeef-cafef00d-01",
	})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, id)

	var got struct {
		EventID      uuid.UUID
		Kind         string
		Payload      []byte
		Traceparent  *string
		OccurredAt   time.Time
		AttemptCount int
		Published    *time.Time
	}
	err = pool.QueryRow(context.Background(),
		`SELECT event_id, kind, payload, traceparent, occurred_at, attempt_count, published_at
		 FROM event_outbox WHERE id = $1`, id).
		Scan(&got.EventID, &got.Kind, &got.Payload, &got.Traceparent, &got.OccurredAt, &got.AttemptCount, &got.Published)
	require.NoError(t, err)

	assert.Equal(t, eventID, got.EventID)
	assert.Equal(t, "run.completed", got.Kind)
	assert.Equal(t, "00-deadbeef-cafef00d-01", *got.Traceparent)
	assert.True(t, occurred.Equal(got.OccurredAt))
	assert.Equal(t, 0, got.AttemptCount)
	assert.Nil(t, got.Published, "fresh row must be unpublished")
	// Postgres jsonb normalizes whitespace; parse semantically instead of
	// string-matching the rendered output.
	var env map[string]any
	require.NoError(t, json.Unmarshal(got.Payload, &env))
	assert.Equal(t, eventID.String(), env["event_id"])
	assert.EqualValues(t, 1, env["version"])
	assert.Equal(t, "run.completed", env["kind"])
}

func TestOutbox_EnqueueFillsMissingEventID(t *testing.T) {
	pool := openIsolatedPool(t)
	orgID := seedOrg(t, pool)
	outbox := eventbus.NewOutbox(pool)

	id, err := outbox.Enqueue(context.Background(), eventbus.Event{
		OrgID: orgID, Kind: "x",
	})
	require.NoError(t, err)

	var eventID uuid.UUID
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT event_id FROM event_outbox WHERE id = $1`, id).Scan(&eventID))
	assert.NotEqual(t, uuid.Nil, eventID, "Enqueue must mint an EventID when caller omits it")
}

func TestOutbox_EnqueueRejectsMissingOrg(t *testing.T) {
	pool := openIsolatedPool(t)
	outbox := eventbus.NewOutbox(pool)

	_, err := outbox.Enqueue(context.Background(), eventbus.Event{Kind: "x"})
	assert.ErrorIs(t, err, eventbus.ErrInvalidEvent)
}

func TestOutbox_EnqueueTxRollsBackWithCallerTx(t *testing.T) {
	// The whole point of the outbox pattern: if the caller's tx is
	// rolled back, the event MUST NOT survive.
	pool := openIsolatedPool(t)
	orgID := seedOrg(t, pool)
	outbox := eventbus.NewOutbox(pool)

	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	require.NoError(t, err)

	_, err = outbox.EnqueueTx(ctx, tx, eventbus.Event{OrgID: orgID, Kind: "must-not-survive"})
	require.NoError(t, err)

	require.NoError(t, tx.Rollback(ctx))

	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM event_outbox WHERE kind = 'must-not-survive'`).Scan(&count))
	assert.Equal(t, 0, count,
		"rolling back the caller tx must also discard the outbox row")
}

func TestOutbox_LagSeconds(t *testing.T) {
	pool := openIsolatedPool(t)
	orgID := seedOrg(t, pool)
	outbox := eventbus.NewOutbox(pool)

	lag, err := outbox.LagSeconds(context.Background(), 20)
	require.NoError(t, err)
	assert.Equal(t, 0.0, lag, "empty outbox → 0s lag")

	_, err = outbox.Enqueue(context.Background(), eventbus.Event{OrgID: orgID, Kind: "x"})
	require.NoError(t, err)
	// Manually back-date created_at so lag is observable without sleeping.
	_, err = pool.Exec(context.Background(),
		`UPDATE event_outbox SET created_at = now() - interval '7 seconds' WHERE kind = 'x'`)
	require.NoError(t, err)

	lag, err = outbox.LagSeconds(context.Background(), 20)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, lag, 6.0)
	assert.LessOrEqual(t, lag, 12.0)
}

func TestOutbox_CleanupPublished(t *testing.T) {
	pool := openIsolatedPool(t)
	orgID := seedOrg(t, pool)
	outbox := eventbus.NewOutbox(pool)
	ctx := context.Background()

	id, err := outbox.Enqueue(ctx, eventbus.Event{OrgID: orgID, Kind: "k"})
	require.NoError(t, err)
	// Mark old-published manually.
	_, err = pool.Exec(ctx,
		`UPDATE event_outbox SET published_at = now() - interval '30 days' WHERE id = $1`, id)
	require.NoError(t, err)

	// Add a fresh published row that must survive cleanup.
	id2, err := outbox.Enqueue(ctx, eventbus.Event{OrgID: orgID, Kind: "k"})
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE event_outbox SET published_at = now() WHERE id = $1`, id2)
	require.NoError(t, err)

	deleted, err := outbox.CleanupPublished(ctx, 7*24*time.Hour)
	require.NoError(t, err)
	assert.EqualValues(t, 1, deleted, "only the 30-day-old row should be cleaned")

	var still int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM event_outbox WHERE id = $1`, id2).Scan(&still))
	assert.Equal(t, 1, still, "fresh published row must survive cleanup")
}


// recorderPublisher captures every Publish call so tests can assert on
// ordering, headers, and counts. The lock is necessary because the
// dispatcher runs goroutines for cleanup + lag.
type recorderPublisher struct {
	mu       sync.Mutex
	messages []recordedMessage
	failN    int   // first N calls return Err
	err      error // error to return while failN > 0
	calls    atomic.Int64
}

type recordedMessage struct {
	Key     string
	Payload []byte
	Headers map[string]string
}

func (r *recorderPublisher) Publish(_ context.Context, key string, payload []byte, headers map[string]string) error {
	r.calls.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failN > 0 {
		r.failN--
		return r.err
	}
	r.messages = append(r.messages, recordedMessage{Key: key, Payload: append([]byte(nil), payload...), Headers: headers})
	return nil
}

func TestDispatcher_PublishesPendingRowsThenMarksThem(t *testing.T) {
	pool := openIsolatedPool(t)
	orgID := seedOrg(t, pool)
	outbox := eventbus.NewOutbox(pool)
	rec := &recorderPublisher{}

	d, err := eventbus.NewDispatcher(outbox, rec, eventbus.DispatcherConfig{
		PollInterval: 20 * time.Millisecond,
		BatchSize:    10,
	}, eventbus.DispatcherMetrics{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	for i := 0; i < 5; i++ {
		_, err := outbox.Enqueue(ctx, eventbus.Event{OrgID: orgID, Kind: "k", Data: i})
		require.NoError(t, err)
	}

	// Wait for the dispatcher to drain.
	require.Eventually(t, func() bool {
		var pending int
		_ = pool.QueryRow(ctx,
			`SELECT count(*) FROM event_outbox WHERE published_at IS NULL`).Scan(&pending)
		return pending == 0
	}, 5*time.Second, 20*time.Millisecond, "dispatcher must drain the queue")

	assert.EqualValues(t, 5, rec.calls.Load(), "all 5 events must be published")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.Len(t, rec.messages, 5)
	for _, m := range rec.messages {
		assert.Equal(t, orgID.String(), m.Key, "partition key must be org_id")
		assert.Equal(t, "k", m.Headers["event-kind"])
		assert.NotEmpty(t, m.Headers["event-id"])
	}
}

func TestDispatcher_RetriesOnPublishFailureThenSucceeds(t *testing.T) {
	pool := openIsolatedPool(t)
	orgID := seedOrg(t, pool)
	outbox := eventbus.NewOutbox(pool)
	// Fail the first 2 publishes; the 3rd succeeds.
	rec := &recorderPublisher{failN: 2, err: errors.New("broker boom")}

	d, err := eventbus.NewDispatcher(outbox, rec, eventbus.DispatcherConfig{
		PollInterval: 20 * time.Millisecond,
		BackoffBase:  10 * time.Millisecond, // tiny so the test doesn't sleep for seconds
		BackoffMax:   100 * time.Millisecond,
		BatchSize:    1,
	}, eventbus.DispatcherMetrics{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	id, err := outbox.Enqueue(ctx, eventbus.Event{OrgID: orgID, Kind: "retryable"})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		var pub *time.Time
		_ = pool.QueryRow(ctx, `SELECT published_at FROM event_outbox WHERE id = $1`, id).Scan(&pub)
		return pub != nil
	}, 5*time.Second, 20*time.Millisecond, "row must eventually be published after retries")

	assert.GreaterOrEqual(t, rec.calls.Load(), int64(3), "needed at least 3 attempts (2 fail + 1 succeed)")

	// attempt_count should reflect the 2 failures (the success doesn't bump).
	var attempts int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT attempt_count FROM event_outbox WHERE id = $1`, id).Scan(&attempts))
	assert.Equal(t, 2, attempts)
}

func TestDispatcher_DeadLettersAfterMaxAttempts(t *testing.T) {
	pool := openIsolatedPool(t)
	orgID := seedOrg(t, pool)
	outbox := eventbus.NewOutbox(pool)
	// Fail forever.
	rec := &recorderPublisher{failN: 1_000_000, err: errors.New("always fails")}

	deadCount := atomic.Int64{}
	d, err := eventbus.NewDispatcher(outbox, rec, eventbus.DispatcherConfig{
		PollInterval: 5 * time.Millisecond,
		BackoffBase:  1 * time.Millisecond,
		BackoffMax:   5 * time.Millisecond,
		BatchSize:    1,
		MaxAttempts:  3,
	}, eventbus.DispatcherMetrics{
		Dead: func(string) { deadCount.Add(1) },
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	id, err := outbox.Enqueue(ctx, eventbus.Event{OrgID: orgID, Kind: "doomed"})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		var attempts int
		_ = pool.QueryRow(ctx, `SELECT attempt_count FROM event_outbox WHERE id = $1`, id).Scan(&attempts)
		return attempts >= 3
	}, 5*time.Second, 10*time.Millisecond, "must accumulate MaxAttempts failures")

	// Hold the test long enough that any further claim attempts would
	// keep climbing — they must NOT, because attempt_count >= MaxAttempts
	// filters the row out of claimBatch.
	time.Sleep(150 * time.Millisecond)

	var finalAttempts int
	var lastErr *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT attempt_count, last_error FROM event_outbox WHERE id = $1`, id).
		Scan(&finalAttempts, &lastErr))
	assert.Equal(t, 3, finalAttempts, "dispatcher must STOP at MaxAttempts (no further retries)")
	assert.NotNil(t, lastErr)
	assert.Contains(t, *lastErr, "always fails")
	assert.GreaterOrEqual(t, deadCount.Load(), int64(1), "Dead metric must fire")
}

func TestDispatcher_TwoInstancesDoNotDoublePublish(t *testing.T) {
	// SELECT FOR UPDATE SKIP LOCKED is the contract that lets multiple
	// dispatcher replicas cooperate. Prove it: enqueue 100 events, run
	// two dispatchers, assert each row was published exactly once.
	pool := openIsolatedPool(t)
	orgID := seedOrg(t, pool)
	outbox := eventbus.NewOutbox(pool)
	rec := &recorderPublisher{}

	mk := func() *eventbus.Dispatcher {
		d, err := eventbus.NewDispatcher(outbox, rec, eventbus.DispatcherConfig{
			PollInterval: 5 * time.Millisecond,
			BatchSize:    10,
		}, eventbus.DispatcherMetrics{})
		require.NoError(t, err)
		return d
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mk().Run(ctx)
	go mk().Run(ctx)

	const N = 100
	for i := 0; i < N; i++ {
		_, err := outbox.Enqueue(ctx, eventbus.Event{OrgID: orgID, Kind: "p", Data: i})
		require.NoError(t, err)
	}

	require.Eventually(t, func() bool {
		var pending int
		_ = pool.QueryRow(ctx,
			`SELECT count(*) FROM event_outbox WHERE published_at IS NULL`).Scan(&pending)
		return pending == 0
	}, 10*time.Second, 20*time.Millisecond)

	assert.EqualValues(t, N, rec.calls.Load(),
		"%d enqueued events must publish exactly %d times across both dispatchers", N, N)
}

func TestDispatcher_RejectsNilDeps(t *testing.T) {
	_, err := eventbus.NewDispatcher(nil, eventbus.PublisherFunc(func(context.Context, string, []byte, map[string]string) error { return nil }), eventbus.DispatcherConfig{}, eventbus.DispatcherMetrics{})
	require.Error(t, err)

	pool := openIsolatedPool(t)
	_, err = eventbus.NewDispatcher(eventbus.NewOutbox(pool), nil, eventbus.DispatcherConfig{}, eventbus.DispatcherMetrics{})
	require.Error(t, err)
}
