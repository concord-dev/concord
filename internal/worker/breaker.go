package worker

import (
	"errors"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/sony/gobreaker"
)

// BreakerConfig tunes the per-host circuit breaker pool. Zero fields fall back to defaults.
type BreakerConfig struct {
	MaxConsecutiveFails uint32
	OpenTimeout         time.Duration
	HalfOpenMaxRequests uint32
	MaxBreakers         int
	OnStateChange       func(host string, from, to gobreaker.State)
}

// ErrCircuitOpen is returned by Execute when the per-host breaker is open.
var ErrCircuitOpen = errors.New("worker: circuit breaker open for receiver")

// Breakers is the per-host pool of gobreaker.CircuitBreaker instances. Nil receiver = disabled.
type Breakers struct {
	cfg BreakerConfig

	mu     sync.Mutex
	pool   map[string]*pooledBreaker
	lruSeq uint64
}

type pooledBreaker struct {
	cb      *gobreaker.CircuitBreaker
	lastUse uint64
}

// NewBreakers constructs a Breakers pool with defaults applied.
func NewBreakers(cfg BreakerConfig) *Breakers {
	if cfg.MaxConsecutiveFails == 0 {
		cfg.MaxConsecutiveFails = 5
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = 30 * time.Second
	}
	if cfg.HalfOpenMaxRequests == 0 {
		cfg.HalfOpenMaxRequests = 1
	}
	if cfg.MaxBreakers <= 0 {
		cfg.MaxBreakers = 10_000
	}
	return &Breakers{
		cfg:  cfg,
		pool: make(map[string]*pooledBreaker),
	}
}

// Execute runs fn behind the per-host breaker keyed off targetURL.
// A nil receiver bypasses the breaker.
func (b *Breakers) Execute(targetURL string, fn func() error) error {
	if b == nil {
		return fn()
	}
	host := hostFromURL(targetURL)
	cb := b.lookupOrCreate(host)

	_, err := cb.Execute(func() (any, error) {
		return nil, fn()
	})
	if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
		return ErrCircuitOpen
	}
	return err
}

func (b *Breakers) lookupOrCreate(host string) *gobreaker.CircuitBreaker {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lruSeq++
	if entry, ok := b.pool[host]; ok {
		entry.lastUse = b.lruSeq
		return entry.cb
	}
	if len(b.pool) >= b.cfg.MaxBreakers {
		var oldestHost string
		var oldest uint64 = ^uint64(0)
		for h, e := range b.pool {
			if e.lastUse < oldest {
				oldest = e.lastUse
				oldestHost = h
			}
		}
		delete(b.pool, oldestHost)
	}
	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        host,
		MaxRequests: b.cfg.HalfOpenMaxRequests,
		Timeout:     b.cfg.OpenTimeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= b.cfg.MaxConsecutiveFails
		},
		OnStateChange: func(name string, from, to gobreaker.State) {
			if b.cfg.OnStateChange != nil {
				b.cfg.OnStateChange(name, from, to)
			}
			slog.Warn("circuit breaker state change",
				slog.String("host", name),
				slog.String("from", from.String()),
				slog.String("to", to.String()))
		},
	})
	b.pool[host] = &pooledBreaker{cb: cb, lastUse: b.lruSeq}
	return cb
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}
