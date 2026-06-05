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
	for i := 0; i < 3; i++ {
		err := b.Execute("http://bad.example/x", func() error { return failErr })
		assert.ErrorIs(t, err, failErr, "while closed, error propagates as-is")
	}
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

	for i := 0; i < 2; i++ {
		_ = b.Execute("http://bad.example/", func() error { return errors.New("boom") })
	}
	assert.ErrorIs(t,
		b.Execute("http://bad.example/", func() error { return nil }),
		worker.ErrCircuitOpen,
		"bad.example breaker must be open")

	err := b.Execute("http://good.example/", func() error { return nil })
	assert.NoError(t, err, "an unrelated host must not share the failure budget")
}

func TestBreakers_HostKeyingIgnoresPath(t *testing.T) {
	b := worker.NewBreakers(worker.BreakerConfig{MaxConsecutiveFails: 2, OpenTimeout: 5 * time.Second})

	for i := 0; i < 2; i++ {
		_ = b.Execute("http://hooks.example/a", func() error { return errors.New("x") })
	}
	for _, path := range []string{"http://hooks.example/a", "http://hooks.example/b", "http://hooks.example/c?q=1"} {
		assert.ErrorIs(t,
			b.Execute(path, func() error { return nil }),
			worker.ErrCircuitOpen,
			"sibling path %q must inherit the host's open state", path)
	}
	err := b.Execute("http://hooks.example:8080/a", func() error { return nil })
	assert.NoError(t, err, "different :port is a different breaker bucket")
}

func TestBreakers_RecoversAfterOpenTimeout(t *testing.T) {
	b := worker.NewBreakers(worker.BreakerConfig{
		MaxConsecutiveFails: 2,
		OpenTimeout:         50 * time.Millisecond, // short so the test isn't slow
		HalfOpenMaxRequests: 1,
	})

	for i := 0; i < 2; i++ {
		_ = b.Execute("http://recover.example/", func() error { return errors.New("x") })
	}
	assert.ErrorIs(t,
		b.Execute("http://recover.example/", func() error { return nil }),
		worker.ErrCircuitOpen)

	time.Sleep(80 * time.Millisecond)
	err := b.Execute("http://recover.example/", func() error { return nil })
	assert.NoError(t, err, "after OpenTimeout the half-open probe should succeed")

	err = b.Execute("http://recover.example/", func() error { return nil })
	assert.NoError(t, err, "after a successful probe the breaker closes")
}

func TestBreakers_NilReceiverIsPassThrough(t *testing.T) {
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
	b := worker.NewBreakers(worker.BreakerConfig{MaxConsecutiveFails: 2, OpenTimeout: 5 * time.Second})
	for i := 0; i < 2; i++ {
		_ = b.Execute("garbage-not-a-url", func() error { return errors.New("x") })
	}
	assert.ErrorIs(t,
		b.Execute("garbage-not-a-url", func() error { return nil }),
		worker.ErrCircuitOpen)
}
