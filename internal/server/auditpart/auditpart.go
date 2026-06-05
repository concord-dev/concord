// Package auditpart owns the audit_event partition-rotation
// background task. concord-server runs one instance of Rotator per
// process, calling EnsureMonthsAhead daily so the partition for next
// month always exists ahead of the rollover.
//
// Why a background task instead of a cron? It keeps the dependency
// surface trivial — one binary, no Kubernetes CronJob to author or
// permission. Multiple replicas calling EnsureAuditPartition
// concurrently is safe (the PL/pgSQL function is idempotent), so
// running this from every replica is fine.
//
// Operators can also call the underlying Store.EnsureAuditPartition
// directly from the runbook (psql + a one-liner) to bootstrap an
// arbitrary month — same code path, same idempotency.
package auditpart

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/concord-dev/concord/internal/store"
)

// Config tunes the Rotator's cadence + look-ahead window.
type Config struct {
	// MonthsAhead is how many months past now we ensure exist. 1 is
	// the minimum for "next-month rollover safe"; 3 gives a healthy
	// buffer against a missed tick from a wedged process. Default 3.
	MonthsAhead int

	// Interval is how often the Rotator wakes up to re-check. Daily
	// (24h) is the sensible default — partitions are cheap, and a
	// daily re-check tolerates clock skew + slightly-late processes.
	Interval time.Duration

	// JitterFraction is the random fraction of Interval added /
	// subtracted on each wake-up so a fleet of replicas doesn't all
	// hit the DB at the same minute. 0.1 = ±10% jitter; default.
	JitterFraction float64
}

// Metrics surfaces partition-rotation telemetry. All optional.
type Metrics struct {
	Created      func(name string)
	Ensured      func(name string) // every successful call, whether or not it created
	Failed       func(err error)
	LookaheadGap func(months int)  // observed gap between newest partition and now+MonthsAhead
}

// Rotator is the background task. Construct via New; start with
// Run(ctx); cancel ctx to stop.
type Rotator struct {
	store   *store.Store
	cfg     Config
	metrics Metrics
	now     func() time.Time
}

// New wires the dependencies. Returns an error when store is nil.
func New(s *store.Store, cfg Config, m Metrics) (*Rotator, error) {
	if s == nil {
		return nil, errors.New("auditpart: New needs a Store")
	}
	if cfg.MonthsAhead <= 0 {
		cfg.MonthsAhead = 3
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 24 * time.Hour
	}
	if cfg.JitterFraction < 0 || cfg.JitterFraction > 1 {
		cfg.JitterFraction = 0.1
	}
	return &Rotator{store: s, cfg: cfg, metrics: m, now: time.Now}, nil
}

// Run is the main loop. Calls EnsureMonthsAhead once immediately to
// front-load the work on startup (so a freshly-deployed pod doesn't
// wait 24h before its first rotation tick), then ticks on Interval +
// jitter. Returns when ctx is cancelled.
func (r *Rotator) Run(ctx context.Context) {
	slog.Info("audit partition rotator: starting",
		slog.Int("months_ahead", r.cfg.MonthsAhead),
		slog.Duration("interval", r.cfg.Interval))
	defer slog.Info("audit partition rotator: stopped")

	r.tickOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.nextDelay()):
			r.tickOnce(ctx)
		}
	}
}

// EnsureMonthsAhead creates every monthly partition from now through
// now + MonthsAhead months that doesn't already exist. Exposed for
// the runbook + tests; the background loop calls it on each tick.
//
// Returns the slice of partitions touched (created OR ensured) in
// chronological order, plus any error from the first failure.
func (r *Rotator) EnsureMonthsAhead(ctx context.Context) ([]store.AuditPartition, error) {
	out := make([]store.AuditPartition, 0, r.cfg.MonthsAhead+1)
	cur := r.now().UTC()
	for i := 0; i <= r.cfg.MonthsAhead; i++ {
		// AddDate handles month-end wraparound (Jan 31 + 1 month →
		// Feb 28/29) correctly; arithmetic on raw durations would
		// drift on long-running pods.
		month := cur.AddDate(0, i, 0)
		p, err := r.store.EnsureAuditPartition(ctx, month)
		if err != nil {
			if r.metrics.Failed != nil {
				r.metrics.Failed(err)
			}
			return out, err
		}
		out = append(out, p)
		if p.Created {
			slog.Info("audit partition created",
				slog.String("name", p.Name),
				slog.Time("range_start", p.RangeStart),
				slog.Time("range_end", p.RangeEnd))
			if r.metrics.Created != nil {
				r.metrics.Created(p.Name)
			}
		}
		if r.metrics.Ensured != nil {
			r.metrics.Ensured(p.Name)
		}
	}
	if r.metrics.LookaheadGap != nil {
		r.metrics.LookaheadGap(r.cfg.MonthsAhead)
	}
	return out, nil
}

// tickOnce wraps EnsureMonthsAhead with the per-tick deadline and a
// silent-log on error (so a transient DB blip doesn't crash the
// process — next tick will retry).
func (r *Rotator) tickOnce(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := r.EnsureMonthsAhead(tickCtx); err != nil {
		slog.Error("audit partition rotation failed; will retry next tick",
			slog.String("err", err.Error()))
	}
}

// nextDelay returns the wait until the next tick. Jitter is applied
// symmetrically around the configured interval so the long-run
// average rate matches the configured interval exactly.
func (r *Rotator) nextDelay() time.Duration {
	if r.cfg.JitterFraction == 0 {
		return r.cfg.Interval
	}
	// Deterministic jitter derived from the current nano time so we
	// don't need a pkg-level RNG (and so tests with a fake clock are
	// reproducible). Range: [1 - jf, 1 + jf] * Interval.
	ns := r.now().UnixNano()
	// xorshift to spread out adjacent calls
	x := uint64(ns)
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	frac := float64(x&0xFFFF) / float64(0xFFFF) // [0, 1]
	mult := 1.0 + r.cfg.JitterFraction*(2*frac-1)
	return time.Duration(float64(r.cfg.Interval) * mult)
}
