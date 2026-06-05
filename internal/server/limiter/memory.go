package limiter

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

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

func (b *MemoryBucket) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}
