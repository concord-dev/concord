package limiter_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"

	"github.com/concord-dev/concord/internal/server/limiter"
)

func TestBucket_AllowsUpToBurstThenDenies(t *testing.T) {
	b := limiter.NewBucket(limiter.Config{Rate: rate.Every(time.Second), Burst: 3})

	for i := 0; i < 3; i++ {
		ok, _ := b.Allow("alice")
		assert.True(t, ok, "first %d requests within burst must pass", i+1)
	}
	ok, ra := b.Allow("alice")
	assert.False(t, ok, "burst+1 must be denied")
	assert.GreaterOrEqual(t, ra, time.Second,
		"Retry-After must round up to at least 1s so clients honour it")
}

func TestBucket_KeysAreIndependent(t *testing.T) {
	// alice exhausting her bucket must not affect bob.
	b := limiter.NewBucket(limiter.Config{Rate: rate.Every(time.Minute), Burst: 1})

	ok, _ := b.Allow("alice")
	assert.True(t, ok)
	denied, _ := b.Allow("alice")
	assert.False(t, denied)

	ok, _ = b.Allow("bob")
	assert.True(t, ok, "bob has his own bucket")
}

func TestBucket_EmptyKeyShortCircuits(t *testing.T) {
	// Anonymous callers without an extractable identity must not collapse
	// into one shared bucket — that would be a self-DoS during traffic spikes.
	b := limiter.NewBucket(limiter.Config{Rate: rate.Every(time.Minute), Burst: 1})
	for i := 0; i < 100; i++ {
		ok, _ := b.Allow("")
		assert.True(t, ok, "empty-key callers must always pass")
	}
}

func TestBucket_IdleKeysEvictedOnNextTouch(t *testing.T) {
	// Use a fake clock so we don't have to actually sleep through the TTL.
	cur := time.Now()
	b := limiter.NewBucket(limiter.Config{Rate: rate.Every(time.Second), Burst: 1, TTL: 5 * time.Second})
	limiter.SetClockForTest(b, func() time.Time { return cur })

	for _, k := range []string{"a", "b", "c"} {
		b.Allow(k)
	}
	assert.Equal(t, 3, b.Size())

	cur = cur.Add(11 * time.Second) // > 2× TTL → GC sweep on next Allow

	b.Allow("d")
	assert.Equal(t, 1, b.Size(),
		"stale a/b/c must be evicted on the next-touch GC sweep")
}

func TestBucket_ConcurrentAllowIsSafe(t *testing.T) {
	b := limiter.NewBucket(limiter.Config{Rate: rate.Every(time.Microsecond), Burst: 1000})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = b.Allow("hot-key")
			}
		}()
	}
	wg.Wait()
	// The assertion here is "no race / no panic". Burst + replenishment
	// makes the exact count nondeterministic.
}
