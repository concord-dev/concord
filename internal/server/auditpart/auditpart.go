package auditpart

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/concord-dev/concord/internal/store"
)

type Config struct {
	MonthsAhead int

	Interval time.Duration

	JitterFraction float64
}

type Metrics struct {
	Created      func(name string)
	Ensured      func(name string) // every successful call, whether or not it created
	Failed       func(err error)
	LookaheadGap func(months int)  // observed gap between newest partition and now+MonthsAhead
}

type Rotator struct {
	store   *store.Store
	cfg     Config
	metrics Metrics
	now     func() time.Time
}

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

func (r *Rotator) EnsureMonthsAhead(ctx context.Context) ([]store.AuditPartition, error) {
	out := make([]store.AuditPartition, 0, r.cfg.MonthsAhead+1)
	cur := r.now().UTC()
	for i := 0; i <= r.cfg.MonthsAhead; i++ {
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

func (r *Rotator) tickOnce(ctx context.Context) {
	tickCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := r.EnsureMonthsAhead(tickCtx); err != nil {
		slog.Error("audit partition rotation failed; will retry next tick",
			slog.String("err", err.Error()))
	}
}

func (r *Rotator) nextDelay() time.Duration {
	if r.cfg.JitterFraction == 0 {
		return r.cfg.Interval
	}
	ns := r.now().UnixNano()
	x := uint64(ns)
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	frac := float64(x&0xFFFF) / float64(0xFFFF) // [0, 1]
	mult := 1.0 + r.cfg.JitterFraction*(2*frac-1)
	return time.Duration(float64(r.cfg.Interval) * mult)
}
