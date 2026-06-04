package limiter_test

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server/limiter"
)

// requireRedis skips the test unless CONCORD_TEST_REDIS_ADDR points at a
// reachable Redis. We deliberately don't auto-start one — CI provides
// redis as a service container; local dev runs `make pg` style
// docker-compose to bring redis up alongside Postgres.
func requireRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("CONCORD_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set CONCORD_TEST_REDIS_ADDR=host:port to run Redis-backed limiter tests")
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  500 * time.Millisecond,
		WriteTimeout: 500 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis at %s not reachable: %v", addr, err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// uniquePrefix gives every test its own Redis keyspace so re-runs and
// parallel runs don't contaminate each other.
func uniquePrefix(t *testing.T) string {
	t.Helper()
	return "concord:rl-test:" + t.Name() + ":" + time.Now().Format("150405.000000") + ":"
}

func TestRedisBucket_AllowsUpToBurstThenDenies(t *testing.T) {
	rdb := requireRedis(t)
	b, err := limiter.NewRedisBucket(rdb, limiter.RedisBucketOptions{
		Config:  limiter.Config{Rate: limiter.Every(time.Hour), Burst: 5},
		Prefix:  uniquePrefix(t),
		Timeout: 500 * time.Millisecond,
	})
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		ok, _ := b.Allow("alice")
		assert.True(t, ok, "first %d within burst must pass", i+1)
	}
	ok, ra := b.Allow("alice")
	assert.False(t, ok, "burst+1 must be denied")
	assert.GreaterOrEqual(t, ra, time.Second,
		"Retry-After must round up to ≥1s for HTTP header use")
}

func TestRedisBucket_KeysAreIndependent(t *testing.T) {
	rdb := requireRedis(t)
	b, err := limiter.NewRedisBucket(rdb, limiter.RedisBucketOptions{
		Config:  limiter.Config{Rate: limiter.Every(time.Hour), Burst: 1},
		Prefix:  uniquePrefix(t),
		Timeout: 500 * time.Millisecond,
	})
	require.NoError(t, err)

	ok, _ := b.Allow("alice")
	assert.True(t, ok)
	denied, _ := b.Allow("alice")
	assert.False(t, denied)

	ok, _ = b.Allow("bob")
	assert.True(t, ok, "bob has his own bucket")
}

func TestRedisBucket_EmptyKeyShortCircuits(t *testing.T) {
	rdb := requireRedis(t)
	b, err := limiter.NewRedisBucket(rdb, limiter.RedisBucketOptions{
		Config:  limiter.Config{Rate: limiter.Every(time.Hour), Burst: 1},
		Prefix:  uniquePrefix(t),
		Timeout: 500 * time.Millisecond,
	})
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		ok, _ := b.Allow("")
		assert.True(t, ok, "empty-key callers must always pass")
	}
}

func TestRedisBucket_RefillsOverTime(t *testing.T) {
	rdb := requireRedis(t)
	// 1 token per 100ms so the test completes quickly.
	b, err := limiter.NewRedisBucket(rdb, limiter.RedisBucketOptions{
		Config:  limiter.Config{Rate: limiter.Every(100 * time.Millisecond), Burst: 1},
		Prefix:  uniquePrefix(t),
		Timeout: 500 * time.Millisecond,
	})
	require.NoError(t, err)

	ok, _ := b.Allow("k")
	assert.True(t, ok, "first burst token")
	denied, _ := b.Allow("k")
	assert.False(t, denied, "second is rate-limited")

	// Wait > 1 token's worth of time and re-attempt.
	time.Sleep(150 * time.Millisecond)
	ok, _ = b.Allow("k")
	assert.True(t, ok, "after refill window a new token is available")
}

func TestRedisBucket_ConcurrentAtomicSpend(t *testing.T) {
	// Atomicity check: with burst=10 and Rate set so refill is negligible
	// during the test, exactly 10 of 200 concurrent Allow calls must
	// succeed. If Lua atomicity is broken we'd see >10 or <10 passes.
	rdb := requireRedis(t)
	b, err := limiter.NewRedisBucket(rdb, limiter.RedisBucketOptions{
		Config:  limiter.Config{Rate: limiter.Every(time.Hour), Burst: 10},
		Prefix:  uniquePrefix(t),
		Timeout: 1 * time.Second,
	})
	require.NoError(t, err)

	const goroutines = 200
	var passes atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := b.Allow("hot"); ok {
				passes.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(10), passes.Load(),
		"Lua bucket must admit exactly burst (=10) of %d concurrent calls", goroutines)
}

func TestRedisBucket_FailsClosedOnUnreachableRedis(t *testing.T) {
	// A standalone client pointed at a port nothing listens on. Each
	// Allow must return (false, ≥1s) and AllowE must surface
	// ErrUnavailable so FailoverBucket can route around it.
	rdb := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1", // reserved port
		DialTimeout: 100 * time.Millisecond,
		MaxRetries:  -1,
	})
	t.Cleanup(func() { _ = rdb.Close() })

	b, err := limiter.NewRedisBucket(rdb, limiter.RedisBucketOptions{
		Config:  limiter.Config{Rate: limiter.Every(time.Hour), Burst: 5},
		Prefix:  "concord:rl-test:unreachable:",
		Timeout: 100 * time.Millisecond,
	})
	require.NoError(t, err)

	ok, ra := b.Allow("k")
	assert.False(t, ok, "fail-closed: unreachable redis denies")
	assert.GreaterOrEqual(t, ra, time.Second)

	_, _, err = b.AllowE("k")
	assert.ErrorIs(t, err, limiter.ErrUnavailable,
		"AllowE must surface ErrUnavailable so FailoverBucket can switch buckets")
}
