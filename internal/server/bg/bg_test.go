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

func TestGo_NestedSpawnsAreTrackedByTheSameWaitGroup(t *testing.T) {
	r := bg.New()
	var outer, inner atomic.Bool
	r.Go(func() {
		time.Sleep(20 * time.Millisecond)
		r.Go(func() {
			time.Sleep(50 * time.Millisecond)
			inner.Store(true)
		})
		outer.Store(true)
	})
	require.NoError(t, r.Wait(context.Background()))
	assert.True(t, outer.Load(), "outer task must complete")
	assert.True(t, inner.Load(),
		"nested task must also complete — without this, a webhook fan-out would lose deliveries during shutdown")
}

func TestGo_RecoversFromPanicsInsteadOfCrashingTheProcess(t *testing.T) {
	r := bg.New()
	r.Go(func() { panic("simulated webhook failure") })

	require.NoError(t, r.Wait(context.Background()))
}

func TestWait_IsCallableMultipleTimes(t *testing.T) {
	r := bg.New()
	r.Go(func() { time.Sleep(5 * time.Millisecond) })
	require.NoError(t, r.Wait(context.Background()))
	require.NoError(t, r.Wait(context.Background()))
}

func TestGo_IsSafeForConcurrentSubmitters(t *testing.T) {
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
