package worker

import (
	"errors"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/sony/gobreaker"
)

// BreakerConfig tunes the per-URL circuit breaker pool used by the
// Executor. A breaker shields the worker from a wedged receiver — once
// MaxConsecutiveFails errors land in a row the breaker opens and every
// subsequent attempt fails fast with ErrCircuitOpen for the
// OpenTimeout, then admits one half-open probe to test recovery.
//
// The state is per-pod, in-memory. Multiple replicas see independent
// breakers, which is fine: a wedged receiver wedges all replicas
// uniformly, so each will trip its own breaker within seconds. We
// deliberately avoid Redis-coordinated breaker state — load-shedding
// doesn't need cross-pod consistency, and the simpler design avoids a
// hard dependency on Redis for the worker's hot path.
type BreakerConfig struct {
	// MaxConsecutiveFails before the breaker opens. Default 5 — same
	// shape as the executor's MaxAttempts so a single 5-attempt
	// retry cycle against a dead receiver trips the breaker exactly
	// once; subsequent rows fail fast without hitting the receiver.
	MaxConsecutiveFails uint32

	// OpenTimeout is how long the breaker stays open before allowing
	// one half-open probe. Default 30s.
	OpenTimeout time.Duration

	// HalfOpenMaxRequests caps in-flight half-open probes. 1 keeps
	// the recovery test cheap; raising it speeds recovery on a high-
	// throughput receiver but risks N concurrent failed deliveries
	// during a half-open probe.
	HalfOpenMaxRequests uint32

	// MaxBreakers caps the number of distinct URL breakers we keep
	// in memory at once. Effectively unbounded (10,000) by default —
	// a single concord-worker servicing > 10k unique receiver URLs
	// is unrealistic. If we ever cross that line the LRU eviction
	// below silently drops the least-recently-used breaker.
	MaxBreakers int

	// OnStateChange, when set, is invoked with (host, oldState,
	// newState) on every transition. Wire this to a Prometheus
	// counter in cmd/concord-worker to surface trips.
	OnStateChange func(host string, from, to gobreaker.State)
}

// ErrCircuitOpen is returned by Breakers.Execute when the per-URL
// breaker is in the open state. Executor classifies this as a
// network_error outcome so the retry path picks it up the same way
// it picks up any other transient failure.
var ErrCircuitOpen = errors.New("worker: circuit breaker open for receiver")

// Breakers is the per-host pool of gobreaker.CircuitBreaker instances.
// Construct via NewBreakers; pass nil to disable circuit breaking
// entirely (Executor degrades to plain HTTP attempts).
//
// Keyed by URL *host* (not full URL) so a single misbehaving receiver
// host trips one breaker regardless of which path the webhook posts
// to. Per-path breakers would be more selective but vastly more
// breakers — almost every webhook to one host points at the same
// path anyway.
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

// NewBreakers constructs a pool. Returns a nil pool when MaxBreakers
// is non-positive — callers should treat a nil *Breakers the same as
// "disabled".
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
// Returns ErrCircuitOpen when the breaker has tripped; otherwise
// returns whatever fn returned. A nil Breakers receiver runs fn
// directly with no breaker — Executor uses this for the "breakers
// disabled" code path.
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

// lookupOrCreate returns the breaker for host, allocating one (and
// possibly evicting the LRU entry) on miss.
func (b *Breakers) lookupOrCreate(host string) *gobreaker.CircuitBreaker {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lruSeq++
	if entry, ok := b.pool[host]; ok {
		entry.lastUse = b.lruSeq
		return entry.cb
	}
	if len(b.pool) >= b.cfg.MaxBreakers {
		// Evict the LRU entry. O(N) at the cap, which we cross
		// rarely — keeps the data structure trivial.
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

// hostFromURL extracts the host[:port] component for keying the pool.
// Malformed URLs fall back to the raw string so a buggy webhook
// registration still gets its own breaker (rather than colliding
// with the empty-host bucket).
func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}
