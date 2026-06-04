package limiter

import (
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

// FailoverBucket wraps a primary Bucket (typically a RedisBucket) with a
// fallback Bucket (typically a tightened MemoryBucket). When the primary
// reports ErrUnavailable, requests fall through to the fallback so a
// single Redis blip can't 503 the auth surface.
//
// The fallback is deliberately tighter than the primary so a long Redis
// outage can't be used to amplify an attack across N pods (each pod would
// otherwise honour its own per-pod budget = N× the original). cmd/server
// constructs the fallback at roughly Rate/N with a similar burst so the
// fleet-wide ceiling during a Redis outage stays close to the configured
// per-key budget.
//
// FailoverBucket records primary errors via OnPrimaryError (set by
// cmd/server to bump a Prometheus counter), and logs a coarse rate-limited
// slog line so an operator can spot a sustained outage in the logs even
// without metrics.
type FailoverBucket struct {
	primary  failoverPrimary
	fallback Bucket

	// errCount is consulted by the logging code path to throttle slog
	// output during an outage. atomic so it's safe under load.
	errCount atomic.Uint64

	// OnPrimaryError, if set, is invoked for every primary failure (NOT
	// throttled). Wire this to a Prometheus counter in cmd/server.
	OnPrimaryError func(err error)
}

// failoverPrimary is the minimum surface FailoverBucket needs from its
// primary: an Allow variant that surfaces a non-nil error on failure so
// the wrapper can distinguish "denied" from "I couldn't reach Redis".
type failoverPrimary interface {
	AllowE(key string) (bool, time.Duration, error)
}

// NewFailoverBucket wires primary + fallback. Returns an error if either
// is nil — both are required.
func NewFailoverBucket(primary failoverPrimary, fallback Bucket) (*FailoverBucket, error) {
	if primary == nil {
		return nil, errors.New("limiter: FailoverBucket needs a non-nil primary")
	}
	if fallback == nil {
		return nil, errors.New("limiter: FailoverBucket needs a non-nil fallback")
	}
	return &FailoverBucket{primary: primary, fallback: fallback}, nil
}

// Allow consults the primary first. On ErrUnavailable, it routes the
// request to the fallback and records the error. Empty keys are handled
// by the inner buckets — FailoverBucket does not short-circuit them
// itself, so a future primary that wanted to bill anonymous traffic
// could.
func (b *FailoverBucket) Allow(key string) (bool, time.Duration) {
	ok, ra, err := b.primary.AllowE(key)
	if err == nil {
		return ok, ra
	}
	if b.OnPrimaryError != nil {
		b.OnPrimaryError(err)
	}
	// Log every 256th failure at warn level so an outage is visible in
	// logs without spamming them. The first failure always logs so the
	// outage is unambiguous in the timeline.
	if n := b.errCount.Add(1); n == 1 || n%256 == 0 {
		slog.Warn("rate-limiter primary unavailable; serving from fallback",
			slog.String("err", err.Error()),
			slog.Uint64("failures_so_far", n))
	}
	return b.fallback.Allow(key)
}
