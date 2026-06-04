package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

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
