package worker_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
	"github.com/concord-dev/concord/internal/worker"
)

func TestRetrier_RetriesFailedDeliveriesUntilSuccess(t *testing.T) {
	s := openIsolatedStore(t)
	orgID, wh := seedOrgAndWebhook(t, s, nil)

	// Receiver: first 2 calls 500, then 200. Counts how many times
	// each is hit.
	rec := newRecordingReceiver(func(seq int64) (int, string) {
		if seq <= 2 {
			return 500, "boom"
		}
		return 200, "ok"
	})
	defer rec.Close()

	// Seed a row whose backoff is already elapsed so the Retrier picks
	// it up on the next tick.
	ctx := context.Background()
	id, _, err := s.UpsertDelivery(ctx, store.UpsertDeliveryParams{
		WebhookID: wh.ID, EventID: uuid.New(), OrgID: orgID, EventKind: "x",
	})
	require.NoError(t, err)
	// Transition the row to 'failed' with next_attempt_at in the past.
	_, err = s.MarkDeliveryFailed(ctx, id, store.AttemptResult{
		AttemptedAt: time.Now(),
		HTTPStatus:  500,
		Error:       "synthetic seed",
		DurationMS:  1,
	}, -1*time.Second, 5)
	require.NoError(t, err)

	// Force webhook URL to point at the test receiver.
	_, err = s.Pool().Exec(ctx, `UPDATE webhook SET url = $1 WHERE id = $2`, rec.URL(), wh.ID)
	require.NoError(t, err)

	executor, err := worker.NewExecutor(s, worker.ExecutorConfig{
		MaxAttempts: 5,
		BackoffBase: 1 * time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
	}, worker.ExecutorMetrics{})
	require.NoError(t, err)

	retrier, err := worker.NewRetrier(s, executor, worker.RetrierConfig{
		PollInterval:  5 * time.Millisecond,
		BusyInterval:  5 * time.Millisecond,
		BatchSize:     10,
	}, worker.RetrierMetrics{})
	require.NoError(t, err)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go retrier.Run(runCtx)

	require.Eventually(t, func() bool {
		d, err := s.GetWebhookDelivery(ctx, id)
		return err == nil && d.Status == store.DeliverySucceeded
	}, 10*time.Second, 50*time.Millisecond,
		"retrier must drive the row to 'succeeded' after enough retries")

	assert.GreaterOrEqual(t, rec.calls.Load(), int64(2),
		"receiver must have been called multiple times (2 fail + 1 succeed = 3)")

	d, err := s.GetWebhookDelivery(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, store.DeliverySucceeded, d.Status)
	assert.NotNil(t, d.SucceededAt)
	assert.Nil(t, d.NextAttemptAt, "succeeded rows must clear next_attempt_at")
}

func TestRetrier_TwoInstancesDoNotDoubleFire(t *testing.T) {
	// SELECT FOR UPDATE SKIP LOCKED is the contract. Prove that two
	// concurrent retriers against the same DB never deliver the same
	// row twice by seeding N rows, running both, then asserting the
	// receiver count == N.
	s := openIsolatedStore(t)
	orgID, wh := seedOrgAndWebhook(t, s, nil)

	rec := newRecordingReceiver(func(int64) (int, string) { return 200, "ok" })
	defer rec.Close()

	ctx := context.Background()
	_, err := s.Pool().Exec(ctx, `UPDATE webhook SET url = $1 WHERE id = $2`, rec.URL(), wh.ID)
	require.NoError(t, err)

	const N = 30
	ids := make([]uuid.UUID, N)
	for i := 0; i < N; i++ {
		id, _, err := s.UpsertDelivery(ctx, store.UpsertDeliveryParams{
			WebhookID: wh.ID, EventID: uuid.New(), OrgID: orgID, EventKind: "x",
		})
		require.NoError(t, err)
		// Force into 'failed' with an elapsed backoff.
		_, err = s.MarkDeliveryFailed(ctx, id, store.AttemptResult{
			AttemptedAt: time.Now(),
			HTTPStatus:  500,
			Error:       "seed",
			DurationMS:  1,
		}, -1*time.Second, 5)
		require.NoError(t, err)
		ids[i] = id
	}

	executor, err := worker.NewExecutor(s, worker.ExecutorConfig{
		MaxAttempts: 5,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	}, worker.ExecutorMetrics{})
	require.NoError(t, err)

	mk := func() *worker.Retrier {
		r, err := worker.NewRetrier(s, executor, worker.RetrierConfig{
			PollInterval: 5 * time.Millisecond,
			BatchSize:    10,
		}, worker.RetrierMetrics{})
		require.NoError(t, err)
		return r
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go mk().Run(runCtx)
	go mk().Run(runCtx)

	require.Eventually(t, func() bool {
		var pending int
		_ = s.Pool().QueryRow(ctx,
			`SELECT count(*) FROM webhook_delivery WHERE status = 'failed'`).Scan(&pending)
		return pending == 0
	}, 15*time.Second, 50*time.Millisecond,
		"both retriers should drain the queue")

	assert.EqualValues(t, N, rec.calls.Load(),
		"%d failed rows must produce exactly %d POSTs across both retriers", N, N)
}

func TestConsumer_DBLevelIdempotencyOnDoubleProcess(t *testing.T) {
	// Simulate a Kafka redelivery: the Consumer is fed the SAME
	// event_id twice; the second iteration must be a no-op because
	// the (webhook_id, event_id) row already exists with status
	// 'succeeded'.
	s := openIsolatedStore(t)
	orgID, wh := seedOrgAndWebhook(t, s, nil)
	rec := newRecordingReceiver(func(int64) (int, string) { return 200, "ok" })
	defer rec.Close()

	ctx := context.Background()
	_, err := s.Pool().Exec(ctx, `UPDATE webhook SET url = $1 WHERE id = $2`, rec.URL(), wh.ID)
	require.NoError(t, err)

	executor, err := worker.NewExecutor(s, worker.ExecutorConfig{},
		worker.ExecutorMetrics{})
	require.NoError(t, err)

	eventID := uuid.New()

	// Simulate the consumer's deliverFirstAttempt path: UpsertDelivery
	// → first time returns created=true, then Executor runs. Second
	// time UpsertDelivery returns created=false; consumer code skips.
	var calls atomic.Int64
	for i := 0; i < 2; i++ {
		id, created, err := s.UpsertDelivery(ctx, store.UpsertDeliveryParams{
			WebhookID: wh.ID, EventID: eventID, OrgID: orgID, EventKind: "x",
		})
		require.NoError(t, err)
		if !created {
			// Mirror the consumer's behaviour for terminal states.
			existing, err := s.GetWebhookDelivery(ctx, id)
			require.NoError(t, err)
			if existing.Status == store.DeliverySucceeded || existing.Status == store.DeliveryDead {
				continue
			}
		}
		_, err = executor.Attempt(ctx, nil, id, "x", rec.URL(), wh.Secret, []byte("{}"), false)
		require.NoError(t, err)
		calls.Add(1)
	}

	// Receiver should have been called exactly ONCE despite two
	// consumer iterations.
	assert.EqualValues(t, 1, rec.calls.Load(),
		"duplicate event_id must not double-fire the receiver")
	assert.EqualValues(t, 1, calls.Load(),
		"only the first iteration should have run the Executor")
}
