package limiter_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server/limiter"
)

// fakePrimary implements failoverPrimary via AllowE so tests can exercise
// FailoverBucket without booting a Redis. The behaviour is set per-call
// from the test by mutating ResultErr / ResultOK / ResultRA.
type fakePrimary struct {
	mu       sync.Mutex
	calls    atomic.Uint64
	ResultOK bool
	ResultRA time.Duration
	Err      error
}

func (f *fakePrimary) AllowE(_ string) (bool, time.Duration, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ResultOK, f.ResultRA, f.Err
}

func TestFailover_PrimaryHealthyServesPrimary(t *testing.T) {
	primary := &fakePrimary{ResultOK: true}
	fallback := limiter.NewMemoryBucket(limiter.Config{
		Rate: limiter.Every(time.Hour), Burst: 1, // very tight; would deny if hit
	})
	// burn the fallback's only token so any fall-through would 429.
	fallback.Allow("x")

	fb, err := limiter.NewFailoverBucket(primary, fallback)
	require.NoError(t, err)

	for i := 0; i < 50; i++ {
		ok, _ := fb.Allow("x")
		assert.True(t, ok, "primary healthy → always primary, never fallback")
	}
	assert.Equal(t, uint64(50), primary.calls.Load())
}

func TestFailover_PrimaryErrorsRouteToFallback(t *testing.T) {
	primary := &fakePrimary{Err: errors.Join(limiter.ErrUnavailable, errors.New("connection refused"))}
	fallback := limiter.NewMemoryBucket(limiter.Config{Rate: limiter.Every(time.Minute), Burst: 2})

	var errCount atomic.Uint64
	fb, err := limiter.NewFailoverBucket(primary, fallback)
	require.NoError(t, err)
	fb.OnPrimaryError = func(error) { errCount.Add(1) }

	// First two must be admitted by the fallback bucket (burst=2);
	// third must be denied.
	ok1, _ := fb.Allow("k")
	ok2, _ := fb.Allow("k")
	ok3, ra3 := fb.Allow("k")
	assert.True(t, ok1, "fallback admits within burst")
	assert.True(t, ok2, "fallback admits within burst")
	assert.False(t, ok3, "fallback denies past burst")
	assert.GreaterOrEqual(t, ra3, time.Second, "deny carries a sane Retry-After")
	assert.Equal(t, uint64(3), errCount.Load(),
		"OnPrimaryError must fire once per primary failure (not once per outage)")
}

func TestFailover_FallbackTighterThanPrimary(t *testing.T) {
	// The whole point of the design: a sustained Redis outage caps each
	// pod at a fraction of the shared budget, so the fleet-wide ceiling
	// during the outage stays close to the configured rate. We model
	// that by allowing the primary to admit 10 in burst but the fallback
	// only 2. When the primary is healthy, all 10 pass. When it fails,
	// only 2 do.
	primary := &fakePrimary{ResultOK: true}
	fallback := limiter.NewMemoryBucket(limiter.Config{Rate: limiter.Every(time.Hour), Burst: 2})
	fb, _ := limiter.NewFailoverBucket(primary, fallback)

	for i := 0; i < 10; i++ {
		ok, _ := fb.Allow("k")
		assert.True(t, ok, "primary healthy: 10 passes")
	}

	// Now make the primary fail and observe the tightened fallback.
	primary.Err = limiter.ErrUnavailable
	primary.ResultOK = false
	pass := 0
	for i := 0; i < 10; i++ {
		ok, _ := fb.Allow("k")
		if ok {
			pass++
		}
	}
	assert.LessOrEqual(t, pass, 2,
		"under outage the fallback enforces its tighter burst (≤2 of 10)")
}

func TestFailover_RequiresBothPrimaryAndFallback(t *testing.T) {
	_, err := limiter.NewFailoverBucket(nil, limiter.NewMemoryBucket(limiter.Config{Rate: 1, Burst: 1}))
	require.Error(t, err)
	_, err = limiter.NewFailoverBucket(&fakePrimary{}, nil)
	require.Error(t, err)
}
