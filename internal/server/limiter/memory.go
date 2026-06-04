package limiter

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// MemoryBucket is the per-pod, in-memory Bucket implementation. Use
// NewMemoryBucket to construct; the zero value is not useful. Allow is
// safe for concurrent use.
type MemoryBucket struct {
	cfg     Config
	mu      sync.Mutex
	entries map[string]*memEntry
	lastGC  time.Time
	now     func() time.Time // injectable for tests
}

type memEntry struct {
	lim      *rate.Limiter
	lastUsed time.Time
}

// NewMemoryBucket constructs a per-pod token-bucket limiter. A zero or
// negative TTL is replaced with a sensible default so callers can omit it.
func NewMemoryBucket(cfg Config) *MemoryBucket {
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	return &MemoryBucket{
		cfg:     cfg,
		entries: make(map[string]*memEntry),
		now:     time.Now,
	}
}

// Allow returns (true, 0) when the caller for `key` has a token to spend,
// (false, retryAfter) when they don't. Empty keys are always allowed; see
// the package doc for why.
func (b *MemoryBucket) Allow(key string) (bool, time.Duration) {
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
		e = &memEntry{lim: rate.NewLimiter(rate.Limit(b.cfg.Rate), b.cfg.Burst)}
		b.entries[key] = e
	}
	e.lastUsed = now

	if e.lim.AllowN(now, 1) {
		return true, 0
	}
	return false, retryAfter(b.cfg.Rate, e.lim.TokensAt(now))
}

// Size returns the number of tracked keys. Test-only.
func (b *MemoryBucket) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}
