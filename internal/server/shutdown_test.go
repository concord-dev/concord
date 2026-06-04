package server_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// TestShutdown_WaitsForInFlightWebhookDelivery is the load-bearing test
// for C5 graceful shutdown. It registers a webhook that deliberately
// takes longer than the HTTP response itself, then submits a run and
// immediately calls Shutdown. Without graceful drain the webhook
// delivery would be cut off when the process exits; with it, Shutdown
// must block until the receiver gets the body.
func TestShutdown_WaitsForInFlightWebhookDelivery(t *testing.T) {
	h := newHarness(t)

	delivered := make(chan struct{}, 1)
	var receiverHits atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow webhook receiver: the body has already started
		// arriving by the time Shutdown is called, but processing it
		// takes 400ms. A non-graceful shutdown would have already
		// returned, dropping this delivery.
		time.Sleep(400 * time.Millisecond)
		receiverHits.Add(1)
		w.WriteHeader(http.StatusOK)
		select {
		case delivered <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(receiver.Close)

	// Register the webhook for the org.
	body := fmt.Sprintf(`{"url":%q,"event_kinds":["run.completed"]}`, receiver.URL)
	resp, raw := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/webhooks", body, h.apiToken)
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "create webhook: %s", raw)

	// Fire a run — Concord publishes run.completed and enqueues the
	// webhook delivery on the tracked background runner.
	submitBody := `{"agent":{"version":"shutdown-test"},"started_at":"2026-05-16T12:00:00Z","completed_at":"2026-05-16T12:00:01Z","summary":{},"findings":[]}`
	resp, _ = h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", submitBody, h.apiToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Now call Shutdown with a generous deadline. It must block until
	// the slow receiver acknowledged the delivery.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, h.c.Shutdown(ctx))
	elapsed := time.Since(start)

	// The receiver's 400ms sleep must have happened inside the Shutdown
	// window, not been cut short. We allow a small margin for scheduling
	// jitter but assert the lower bound robustly.
	assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(350),
		"Shutdown must block for at least the receiver's 400ms processing — proving drain actually waits")
	assert.Equal(t, int32(1), receiverHits.Load(),
		"the webhook receiver must have been hit exactly once before Shutdown returned")
	select {
	case <-delivered:
	default:
		t.Fatal("receiver did not signal delivery — drain may have returned before the body was processed")
	}
}

// TestShutdown_TimesOutWhenBackgroundOutlastsBudget guards the other
// direction: a wedged background task must NOT block shutdown forever.
// Operators waiting on SIGTERM during a K8s rolling deploy need the
// deadline to actually hold.
func TestShutdown_TimesOutWhenBackgroundOutlastsBudget(t *testing.T) {
	h := newHarness(t)

	// A receiver that never responds — emulates a wedged downstream.
	wedged := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Block longer than the shutdown deadline.
		time.Sleep(10 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(wedged.Close)

	body := fmt.Sprintf(`{"url":%q,"event_kinds":["run.completed"]}`, wedged.URL)
	resp, raw := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/webhooks", body, h.apiToken)
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "create webhook: %s", raw)

	submitBody := `{"agent":{"version":"shutdown-test"},"started_at":"2026-05-16T12:00:00Z","completed_at":"2026-05-16T12:00:01Z","summary":{},"findings":[]}`
	resp, _ = h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", submitBody, h.apiToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := h.c.Shutdown(ctx)
	elapsed := time.Since(start)

	require.Error(t, err, "Shutdown must surface ctx.Err() when the drain exceeds its budget")
	assert.ErrorIs(t, err, context.DeadlineExceeded,
		"a wedged background task must not extend shutdown past its deadline — operators need that guarantee")
	assert.Less(t, elapsed.Milliseconds(), int64(1000),
		"Shutdown must return promptly once the deadline trips — got %dms", elapsed.Milliseconds())
}

// TestShutdown_NoInFlightWorkReturnsImmediately is the happy path: no
// outstanding webhooks/emails, Shutdown must not introduce artificial
// latency on a clean SIGTERM.
func TestShutdown_NoInFlightWorkReturnsImmediately(t *testing.T) {
	h := newHarness(t)
	start := time.Now()
	require.NoError(t, h.c.Shutdown(context.Background()))
	assert.Less(t, time.Since(start).Milliseconds(), int64(100),
		"clean Shutdown with no background work must return promptly — anything > 100ms is a regression")
}

// TestShutdown_IsIdempotent guards against the cmd/server signal path
// reaching Concord.Shutdown twice (e.g. SIGTERM followed by a second
// signal). A second call with no in-flight work must return promptly and
// without error.
func TestShutdown_IsIdempotent(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.c.Shutdown(context.Background()))
	require.NoError(t, h.c.Shutdown(context.Background()),
		"a second Shutdown call must be a no-op — operators may signal twice during a slow drain")
	_ = store.RunSucceeded
}
