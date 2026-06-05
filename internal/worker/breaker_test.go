package worker_test

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sony/gobreaker"
	"github.com/stretchr/testify/assert"

	"github.com/concord-dev/concord/internal/worker"
)

func TestBreakers_OpensAfterMaxConsecutiveFails(t *testing.T) {
	var stateChanges atomic.Int32
	b := worker.NewBreakers(worker.BreakerConfig{
		MaxConsecutiveFails: 3,
		OpenTimeout:         5 * time.Second,
		OnStateChange:       func(_ string, _, _ gobreaker.State) { stateChanges.Add(1) },
	})

	failErr := errors.New("upstream 500")
	// Trip with 3 consecutive failures.
	for i := 0; i < 3; i++ {
		err := b.Execute("http://bad.example/x", func() error { return failErr })
		assert.ErrorIs(t, err, failErr, "while closed, error propagates as-is")
	}
	// 4th attempt should fail-fast as ErrCircuitOpen — handler not invoked.
	var invoked atomic.Int32
	err := b.Execute("http://bad.example/x", func() error {
		invoked.Add(1)
		return nil
	})
	assert.ErrorIs(t, err, worker.ErrCircuitOpen,
		"after MaxConsecutiveFails the breaker must open")
	assert.Zero(t, invoked.Load(), "open-state breaker must NOT call the handler")
	assert.GreaterOrEqual(t, stateChanges.Load(), int32(1),
		"at least one transition (closed→open) must be reported via OnStateChange")
}

func TestBreakers_PerHostIsolation(t *testing.T) {
	b := worker.NewBreakers(worker.BreakerConfig{
		MaxConsecutiveFails: 2,
		OpenTimeout:         5 * time.Second,
	})

	// Trip the breaker for bad.example.
	for i := 0; i < 2; i++ {
		_ = b.Execute("http://bad.example/", func() error { return errors.New("boom") })
	}
	assert.ErrorIs(t,
		b.Execute("http://bad.example/", func() error { return nil }),
		worker.ErrCircuitOpen,
		"bad.example breaker must be open")

	// good.example is on a different host → its breaker is independent.
	err := b.Execute("http://good.example/", func() error { return nil })
	assert.NoError(t, err, "an unrelated host must not share the failure budget")
}

func TestBreakers_HostKeyingIgnoresPath(t *testing.T) {
	// All three URLs map to the same host bucket, so one failing path
	// trips the breaker for sibling paths too. That's deliberate: a
	// receiver that's down is down for every endpoint.
	b := worker.NewBreakers(worker.BreakerConfig{MaxConsecutiveFails: 2, OpenTimeout: 5 * time.Second})

	for i := 0; i < 2; i++ {
		_ = b.Execute("http://hooks.example/a", func() error { return errors.New("x") })
	}
	// Sibling paths on the same host:port share the breaker.
	for _, path := range []string{"http://hooks.example/a", "http://hooks.example/b", "http://hooks.example/c?q=1"} {
		assert.ErrorIs(t,
			b.Execute(path, func() error { return nil }),
			worker.ErrCircuitOpen,
			"sibling path %q must inherit the host's open state", path)
	}
	// Different host:port (explicit non-default port) is a different
	// identity — the breaker isolates it.
	err := b.Execute("http://hooks.example:8080/a", func() error { return nil })
	assert.NoError(t, err, "different :port is a different breaker bucket")
}

func TestBreakers_RecoversAfterOpenTimeout(t *testing.T) {
	b := worker.NewBreakers(worker.BreakerConfig{
		MaxConsecutiveFails: 2,
		OpenTimeout:         50 * time.Millisecond, // short so the test isn't slow
		HalfOpenMaxRequests: 1,
	})

	// Trip
	for i := 0; i < 2; i++ {
		_ = b.Execute("http://recover.example/", func() error { return errors.New("x") })
	}
	assert.ErrorIs(t,
		b.Execute("http://recover.example/", func() error { return nil }),
		worker.ErrCircuitOpen)

	// Wait for the open window to expire, then a successful probe
	// should close the breaker.
	time.Sleep(80 * time.Millisecond)
	err := b.Execute("http://recover.example/", func() error { return nil })
	assert.NoError(t, err, "after OpenTimeout the half-open probe should succeed")

	// Subsequent calls go through normally.
	err = b.Execute("http://recover.example/", func() error { return nil })
	assert.NoError(t, err, "after a successful probe the breaker closes")
}

func TestBreakers_NilReceiverIsPassThrough(t *testing.T) {
	// A nil *Breakers (Executor with breakers disabled) must run the
	// handler verbatim — keeps the disabled code path zero-cost.
	var ran atomic.Int32
	var b *worker.Breakers
	err := b.Execute("http://anything", func() error {
		ran.Add(1)
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, int32(1), ran.Load())
}

func TestBreakers_MalformedURLGetsItsOwnBucket(t *testing.T) {
	// A malformed URL still works (host extraction falls back to the
	// raw string); it just doesn't share buckets with anything else.
	b := worker.NewBreakers(worker.BreakerConfig{MaxConsecutiveFails: 2, OpenTimeout: 5 * time.Second})
	for i := 0; i < 2; i++ {
		_ = b.Execute("garbage-not-a-url", func() error { return errors.New("x") })
	}
	assert.ErrorIs(t,
		b.Execute("garbage-not-a-url", func() error { return nil }),
		worker.ErrCircuitOpen)
}
