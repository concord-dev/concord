package worker_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
	"github.com/concord-dev/concord/internal/worker"
)

// ─── harness ─────────────────────────────────────────────────────────

const defaultTestDSN = "postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable"

// openIsolatedStore creates a fresh per-test database with migrations
// applied. Mirrors the pattern in internal/store and internal/eventbus.
func openIsolatedStore(t *testing.T) *store.Store {
	t.Helper()
	baseDSN := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if baseDSN == "" {
		baseDSN = defaultTestDSN
	}
	u, err := url.Parse(baseDSN)
	require.NoError(t, err)
	u.Path = "/postgres"
	ctlDSN := u.String()

	dbName := "concord_w_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctl, err := pgx.Connect(ctx, ctlDSN)
	if err != nil {
		t.Skipf("postgres unreachable: %v", err)
	}
	_, err = ctl.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %q`, dbName))
	_ = ctl.Close(ctx)
	require.NoError(t, err)

	u.Path = "/" + dbName
	s, err := store.Open(ctx, u.String(), store.PoolOptions{MaxConns: 8, MinConns: 1})
	require.NoError(t, err)
	require.NoError(t, s.Migrate(ctx))

	t.Cleanup(func() {
		s.Close()
		dropCtx, dc := context.WithTimeout(context.Background(), 10*time.Second)
		defer dc()
		c, err := pgx.Connect(dropCtx, ctlDSN)
		if err != nil {
			return
		}
		defer c.Close(dropCtx)
		_, _ = c.Exec(dropCtx,
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
			dbName)
		_, _ = c.Exec(dropCtx, fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, dbName))
	})
	return s
}

func seedOrgAndWebhook(t *testing.T, s *store.Store, allowed []string) (uuid.UUID, store.Webhook) {
	t.Helper()
	ctx := context.Background()
	org, err := s.CreateOrganization(ctx, "test org", "test-"+uuid.NewString()[:8])
	require.NoError(t, err)
	wh, secret, err := s.CreateWebhook(ctx, store.CreateWebhookParams{
		OrgID:      org.ID,
		URL:        "http://placeholder",
		EventKinds: allowed,
		Enabled:    true,
	})
	require.NoError(t, err)
	// The Executor signs against wh.Secret; CreateWebhook only returns
	// the plaintext once, so stash it on the returned struct.
	wh.Secret = secret
	return org.ID, wh
}

// recordingReceiver is a test HTTP server that records every received
// request and returns a configurable status. Used to drive the
// Executor's HTTP path without touching the network. Safe for
// concurrent use by multiple retriers.
type recordingReceiver struct {
	srv     *httptest.Server
	mu      sync.Mutex
	records []recordedRequest
	calls   atomic.Int64
	respond func(seq int64) (status int, body string)
}

type recordedRequest struct {
	Body      []byte
	Signature string
	Kind      string
}

func newRecordingReceiver(respond func(seq int64) (int, string)) *recordingReceiver {
	r := &recordingReceiver{respond: respond}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		seq := r.calls.Add(1)
		body := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(body)
		r.mu.Lock()
		r.records = append(r.records, recordedRequest{
			Body:      body,
			Signature: req.Header.Get("X-Concord-Signature"),
			Kind:      req.Header.Get("X-Concord-Event"),
		})
		r.mu.Unlock()
		status, respBody := r.respond(seq)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	return r
}

func (r *recordingReceiver) Close() { r.srv.Close() }
func (r *recordingReceiver) URL() string { return r.srv.URL }

// ─── Executor tests ──────────────────────────────────────────────────

func TestExecutor_2xxMarksSucceeded(t *testing.T) {
	s := openIsolatedStore(t)
	orgID, wh := seedOrgAndWebhook(t, s, nil)
	rec := newRecordingReceiver(func(int64) (int, string) { return 200, "ok" })
	defer rec.Close()

	exec, err := worker.NewExecutor(s, worker.ExecutorConfig{}, worker.ExecutorMetrics{})
	require.NoError(t, err)

	body := []byte(`{"version":1,"event_id":"abc","kind":"x"}`)
	eventID := uuid.New()
	id, created, err := s.UpsertDelivery(context.Background(), store.UpsertDeliveryParams{
		WebhookID: wh.ID, EventID: eventID, OrgID: orgID, EventKind: "x",
	})
	require.NoError(t, err)
	assert.True(t, created)

	status, err := exec.Attempt(context.Background(), nil, id, "x", rec.URL(), wh.Secret, body, false)
	require.NoError(t, err)
	assert.Equal(t, store.DeliverySucceeded, status)
	assert.EqualValues(t, 1, rec.calls.Load())

	// Verify the HMAC signature the receiver got matches what an
	// independent verifier would compute.
	recMac := hmac.New(sha256.New, []byte(wh.Secret))
	recMac.Write(body)
	want := "sha256=" + hex.EncodeToString(recMac.Sum(nil))
	rec.mu.Lock()
	gotSig := rec.records[0].Signature
	rec.mu.Unlock()
	assert.Equal(t, want, gotSig)

	// Row state should reflect success.
	d, err := s.GetWebhookDelivery(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, store.DeliverySucceeded, d.Status)
	assert.Equal(t, 1, d.AttemptCount)
	assert.NotNil(t, d.SucceededAt)
	assert.Nil(t, d.NextAttemptAt)

	// attempts_log should contain one entry.
	var log []map[string]any
	require.NoError(t, json.Unmarshal(d.AttemptsLog, &log))
	assert.Len(t, log, 1)
}

func TestExecutor_Non2xxMarksFailedWithBackoff(t *testing.T) {
	s := openIsolatedStore(t)
	orgID, wh := seedOrgAndWebhook(t, s, nil)
	rec := newRecordingReceiver(func(int64) (int, string) { return 500, "boom" })
	defer rec.Close()

	exec, err := worker.NewExecutor(s, worker.ExecutorConfig{
		MaxAttempts: 5,
		BackoffBase: 1 * time.Second,
		BackoffMax:  60 * time.Second,
	}, worker.ExecutorMetrics{})
	require.NoError(t, err)

	id, _, err := s.UpsertDelivery(context.Background(), store.UpsertDeliveryParams{
		WebhookID: wh.ID, EventID: uuid.New(), OrgID: orgID, EventKind: "x",
	})
	require.NoError(t, err)
	status, err := exec.Attempt(context.Background(), nil, id, "x", rec.URL(), wh.Secret, []byte("{}"), false)
	require.NoError(t, err)
	assert.Equal(t, store.DeliveryFailed, status)

	d, err := s.GetWebhookDelivery(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, store.DeliveryFailed, d.Status)
	assert.Equal(t, 1, d.AttemptCount)
	assert.Equal(t, 500, d.LastHTTPStatus)
	assert.Contains(t, d.LastError, "non-2xx response 500")
	require.NotNil(t, d.NextAttemptAt)
	assert.True(t, d.NextAttemptAt.After(time.Now()),
		"failed row must have next_attempt_at in the future")
}

func TestExecutor_DeadAfterMaxAttempts(t *testing.T) {
	s := openIsolatedStore(t)
	orgID, wh := seedOrgAndWebhook(t, s, nil)
	rec := newRecordingReceiver(func(int64) (int, string) { return 500, "boom" })
	defer rec.Close()

	exec, err := worker.NewExecutor(s, worker.ExecutorConfig{
		MaxAttempts: 3,
		BackoffBase: 1 * time.Millisecond,
		BackoffMax:  5 * time.Millisecond,
	}, worker.ExecutorMetrics{})
	require.NoError(t, err)

	id, _, err := s.UpsertDelivery(context.Background(), store.UpsertDeliveryParams{
		WebhookID: wh.ID, EventID: uuid.New(), OrgID: orgID, EventKind: "x",
	})
	require.NoError(t, err)

	// Three attempts → on the third, transition to 'dead'.
	for i := 0; i < 3; i++ {
		_, err := exec.Attempt(context.Background(), nil, id, "x", rec.URL(), wh.Secret, []byte("{}"), false)
		require.NoError(t, err)
	}

	d, err := s.GetWebhookDelivery(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, store.DeliveryDead, d.Status)
	assert.Equal(t, 3, d.AttemptCount)
	assert.Nil(t, d.NextAttemptAt, "dead rows must have NULL next_attempt_at")
}

func TestExecutor_NetworkErrorIsClassifiedAndCaptured(t *testing.T) {
	s := openIsolatedStore(t)
	orgID, wh := seedOrgAndWebhook(t, s, nil)

	exec, err := worker.NewExecutor(s, worker.ExecutorConfig{
		HTTPClient: &http.Client{Timeout: 100 * time.Millisecond},
	}, worker.ExecutorMetrics{})
	require.NoError(t, err)

	id, _, err := s.UpsertDelivery(context.Background(), store.UpsertDeliveryParams{
		WebhookID: wh.ID, EventID: uuid.New(), OrgID: orgID, EventKind: "x",
	})
	require.NoError(t, err)

	// Connect to a port nothing listens on → network error.
	status, err := exec.Attempt(context.Background(), nil, id, "x", "http://127.0.0.1:1", wh.Secret, []byte("{}"), false)
	require.NoError(t, err)
	assert.Equal(t, store.DeliveryFailed, status)

	d, err := s.GetWebhookDelivery(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, 0, d.LastHTTPStatus, "network error → http_status = 0")
	assert.Contains(t, d.LastError, "network:")
}

func TestExecutor_BackoffForAttempt(t *testing.T) {
	cfg := worker.ExecutorConfig{BackoffBase: time.Second, BackoffMax: 60 * time.Second}
	// 1 → 1s, 2 → 2s, 3 → 4s, 4 → 8s, 5 → 16s.
	for i, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 8 * time.Second, 5: 16 * time.Second} {
		got := worker.BackoffForAttempt(cfg, i)
		assert.Equal(t, want, got, "attempt %d", i)
	}
	// Cap at BackoffMax.
	cap := worker.BackoffForAttempt(cfg, 30)
	assert.Equal(t, 60*time.Second, cap, "capped at BackoffMax")
}
