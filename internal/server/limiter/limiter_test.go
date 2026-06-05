package limiter_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/concord-dev/concord/internal/server/limiter"
)

func TestMemoryBucket_AllowsUpToBurstThenDenies(t *testing.T) {
	b := limiter.NewMemoryBucket(limiter.Config{Rate: limiter.Every(time.Second), Burst: 3})

	for i := 0; i < 3; i++ {
		ok, _ := b.Allow("alice")
		assert.True(t, ok, "first %d requests within burst must pass", i+1)
	}
	ok, ra := b.Allow("alice")
	assert.False(t, ok, "burst+1 must be denied")
	assert.GreaterOrEqual(t, ra, time.Second,
		"Retry-After must round up to at least 1s so clients honour it")
}

func TestMemoryBucket_KeysAreIndependent(t *testing.T) {
	b := limiter.NewMemoryBucket(limiter.Config{Rate: limiter.Every(time.Minute), Burst: 1})

	ok, _ := b.Allow("alice")
	assert.True(t, ok)
	denied, _ := b.Allow("alice")
	assert.False(t, denied)

	ok, _ = b.Allow("bob")
	assert.True(t, ok, "bob has his own bucket")
}

func TestMemoryBucket_EmptyKeyShortCircuits(t *testing.T) {
	b := limiter.NewMemoryBucket(limiter.Config{Rate: limiter.Every(time.Minute), Burst: 1})
	for i := 0; i < 100; i++ {
		ok, _ := b.Allow("")
		assert.True(t, ok, "empty-key callers must always pass")
	}
}

func TestMemoryBucket_IdleKeysEvictedOnNextTouch(t *testing.T) {
	cur := time.Now()
	b := limiter.NewMemoryBucket(limiter.Config{Rate: limiter.Every(time.Second), Burst: 1, TTL: 5 * time.Second})
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

func TestMemoryBucket_ConcurrentAllowIsSafe(t *testing.T) {
	b := limiter.NewMemoryBucket(limiter.Config{Rate: limiter.Every(time.Microsecond), Burst: 1000})
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
}
