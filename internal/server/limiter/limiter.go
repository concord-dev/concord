// Package limiter is the server's in-memory token-bucket rate limiter. It
// guards the handful of endpoints where an unauthenticated caller can burn
// compute (login, password-reset request) or guess a secret (invitation
// accept, password-reset confirm).
//
// Each Bucket holds a map of `key → *rate.Limiter` and a coarse TTL eviction
// policy so the map can't grow without bound when callers rotate IPs or
// emails. Single-process by design — moving to a distributed limiter
// (Redis/Memcached) is a separate piece of work and is not needed until the
// server is horizontally scaled.
package limiter

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Config configures a Bucket. Rate is the steady-state token replenishment
// rate; Burst is the max instant burst above the rate (and the bucket's
// initial fill). TTL is how long an unseen key is kept around before the
// next-touch GC sweeps it — sized so a legitimate user idling a few minutes
// doesn't lose their bucket state, but a one-off scanner's IP doesn't pin
// memory forever.
type Config struct {
	Rate  rate.Limit
	Burst int
	TTL   time.Duration
}

// Bucket is a keyed token-bucket limiter. Use NewBucket to construct;
// the zero value is not useful. Allow is safe for concurrent use.
type Bucket struct {
	cfg     Config
	mu      sync.Mutex
	entries map[string]*entry
	lastGC  time.Time
	now     func() time.Time // injectable for tests
}

type entry struct {
	lim      *rate.Limiter
	lastUsed time.Time
}

// NewBucket constructs a Bucket. A zero or negative TTL is replaced with a
// sensible default so callers can omit it.
func NewBucket(cfg Config) *Bucket {
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	return &Bucket{
		cfg:     cfg,
		entries: make(map[string]*entry),
		now:     time.Now,
	}
}

// Allow returns (true, 0) when the caller for `key` has a token to spend.
// On deny it returns (false, retryAfter) — retryAfter is the duration until
// the next token would be available, rounded up to whole seconds for use
// in the HTTP Retry-After header. Empty keys are always allowed (callers
// pass an empty string when they can't determine an identity to bill —
// the alternative is collapsing every anonymous caller into one bucket,
// which is a self-inflicted DoS).
func (b *Bucket) Allow(key string) (bool, time.Duration) {
	if key == "" {
		return true, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if now.Sub(b.lastGC) > b.cfg.TTL {
		for k, e := range b.entries {
			if now.Sub(e.lastUsed) > b.cfg.TTL {
				delete(b.entries, k)
			}
		}
		b.lastGC = now
	}

	e, ok := b.entries[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(b.cfg.Rate, b.cfg.Burst)}
		b.entries[key] = e
	}
	e.lastUsed = now

	if e.lim.AllowN(now, 1) {
		return true, 0
	}
	return false, retryAfter(b.cfg.Rate, e.lim.TokensAt(now))
}

// Size returns the number of tracked keys. Test-only.
func (b *Bucket) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}

// retryAfter is a coarse estimate: time until the bucket has at least one
// full token. Rounded up to whole seconds because that's the Retry-After
// header's resolution.
func retryAfter(r rate.Limit, tokens float64) time.Duration {
	need := 1.0 - tokens
	if need <= 0 || r <= 0 {
		return time.Second
	}
	d := time.Duration(need / float64(r) * float64(time.Second))
	if d < time.Second {
		return time.Second
	}
	return d.Round(time.Second)
}
