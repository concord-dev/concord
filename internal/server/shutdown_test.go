package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

func TestShutdown_NoInFlightWorkReturnsImmediately(t *testing.T) {
	h := newHarness(t)
	start := time.Now()
	require.NoError(t, h.c.Shutdown(context.Background()))
	assert.Less(t, time.Since(start).Milliseconds(), int64(100),
		"clean Shutdown with no background work must return promptly — anything > 100ms is a regression")
}

func TestShutdown_IsIdempotent(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.c.Shutdown(context.Background()))
	require.NoError(t, h.c.Shutdown(context.Background()),
		"a second Shutdown call must be a no-op — operators may signal twice during a slow drain")
	_ = store.RunSucceeded
}
