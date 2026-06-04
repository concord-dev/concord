package bg_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server/bg"
)

func TestGo_WaitDrainsAllScheduledTasks(t *testing.T) {
	r := bg.New()
	var n atomic.Int32
	for i := 0; i < 50; i++ {
		r.Go(func() {
			time.Sleep(5 * time.Millisecond)
			n.Add(1)
		})
	}
	require.NoError(t, r.Wait(context.Background()))
	assert.Equal(t, int32(50), n.Load(),
		"every scheduled task must run before Wait returns — that's the whole point")
}

func TestWait_ReturnsContextErrorWhenTasksOutlastTheDeadline(t *testing.T) {
	r := bg.New()
	r.Go(func() { time.Sleep(500 * time.Millisecond) })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := r.Wait(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded,
		"a shutdown that times out must surface context.DeadlineExceeded so operators see WHY the drain didn't complete")
}

func TestGo_AfterWaitIsDroppedNotLeaked(t *testing.T) {
	// After shutdown starts, new Go calls must be no-ops. Otherwise a
	// late-arriving HTTP handler could spawn work the Wait already returned
	// from — undefined behavior at best, hung shutdown at worst.
	r := bg.New()
	require.NoError(t, r.Wait(context.Background()))
	var ran atomic.Bool
	r.Go(func() { ran.Store(true) })
	time.Sleep(50 * time.Millisecond)
	assert.False(t, ran.Load(),
		"Go submissions after Wait must be dropped — Wait already promised drain completion")
}

func TestGo_RecoversFromPanicsInsteadOfCrashingTheProcess(t *testing.T) {
	// A misbehaving webhook receiver / TLS bug must not take down the
	// whole server. Goroutines panic-recover with a slog line.
	r := bg.New()
	r.Go(func() { panic("simulated webhook failure") })

	// If the goroutine did NOT recover, the runtime would crash the test
	// process. Surviving Wait() proves recovery works.
	require.NoError(t, r.Wait(context.Background()))
}

func TestWait_IsCallableMultipleTimes(t *testing.T) {
	// Belt-and-braces: cmd/server has two shutdown paths (signal + error)
	// that might both reach Concord.Shutdown. Wait must be idempotent.
	r := bg.New()
	r.Go(func() { time.Sleep(5 * time.Millisecond) })
	require.NoError(t, r.Wait(context.Background()))
	require.NoError(t, r.Wait(context.Background()))
}

func TestGo_IsSafeForConcurrentSubmitters(t *testing.T) {
	// Real call sites are HTTP handlers running concurrently. Spawning
	// from multiple goroutines must not race on the underlying WaitGroup
	// (the data race would surface under -race).
	r := bg.New()
	var n atomic.Int32
	var submitters sync.WaitGroup
	for i := 0; i < 20; i++ {
		submitters.Add(1)
		go func() {
			defer submitters.Done()
			for j := 0; j < 50; j++ {
				r.Go(func() { n.Add(1) })
			}
		}()
	}
	submitters.Wait()
	require.NoError(t, r.Wait(context.Background()))
	assert.Equal(t, int32(20*50), n.Load())
}
