package limiter

import (
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

type FailoverBucket struct {
	primary  failoverPrimary
	fallback Bucket

	errCount atomic.Uint64

	OnPrimaryError func(err error)
}

type failoverPrimary interface {
	AllowE(key string) (bool, time.Duration, error)
}

func NewFailoverBucket(primary failoverPrimary, fallback Bucket) (*FailoverBucket, error) {
	if primary == nil {
		return nil, errors.New("limiter: FailoverBucket needs a non-nil primary")
	}
	if fallback == nil {
		return nil, errors.New("limiter: FailoverBucket needs a non-nil fallback")
	}
	return &FailoverBucket{primary: primary, fallback: fallback}, nil
}

func (b *FailoverBucket) Allow(key string) (bool, time.Duration) {
	ok, ra, err := b.primary.AllowE(key)
	if err == nil {
		return ok, ra
	}
	if b.OnPrimaryError != nil {
		b.OnPrimaryError(err)
	}
	if n := b.errCount.Add(1); n == 1 || n%256 == 0 {
		slog.Warn("rate-limiter primary unavailable; serving from fallback",
			slog.String("err", err.Error()),
			slog.Uint64("failures_so_far", n))
	}
	return b.fallback.Allow(key)
}
