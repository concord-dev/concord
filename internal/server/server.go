package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/concord-dev/concord/internal/config"
	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/eventbus"
	"github.com/concord-dev/concord/internal/notify/mail"
	"github.com/concord-dev/concord/internal/otelx"
	"github.com/concord-dev/concord/internal/server/bg"
	"github.com/concord-dev/concord/internal/server/auditpart"
	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/server/handlers/auth"
	"github.com/concord-dev/concord/internal/server/handlers/public"
	"github.com/concord-dev/concord/internal/server/idempotency"
	"github.com/concord-dev/concord/internal/server/limiter"
	"github.com/concord-dev/concord/internal/server/metrics"
	"github.com/concord-dev/concord/internal/store"
)

type Concord struct {
	Controls           []controls.Loaded
	Config             *config.Config
	Store              *store.Store
	OperatorToken      string // SaaS-operator back-door token; gates /operator/v1/*
	Version            string
	SessionTTL         time.Duration
	CORSAllowedOrigins []string // exact-match list; empty disables CORS

	bus        *bus.Bus
	metrics    *metrics.Metrics
	mailer     mail.Mailer
	bg         *bg.Runner
	tracing    *otelx.Provider
	authLimits auth.Limits
	pubLimits  public.Limits

	outbox     *eventbus.Outbox
	dispatcher *eventbus.Dispatcher
	dispCancel context.CancelFunc // stops the dispatcher loop in Shutdown

	idempotency func(http.Handler) http.Handler

	auditRotator     *auditpart.Rotator
	auditRotCancel   context.CancelFunc
}

type Options struct {
	ControlsDir        string
	ConfigPath         string
	Store              *store.Store
	OperatorToken      string
	Version            string
	SessionTTL         time.Duration
	CORSAllowedOrigins []string
	SMTP mail.Config

	Tracing *otelx.Provider

	RedisLimiter *redis.Client

	LimiterFallbackTighten float64

	EventPublisher eventbus.Publisher

	DispatcherConfig eventbus.DispatcherConfig
}

func NewConcord(opts Options) (*Concord, error) {
	if opts.Store == nil {
		return nil, errors.New("store is required")
	}
	applyDefaults(&opts)

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	loaded, err := controls.Load(opts.ControlsDir)
	if err != nil {
		return nil, fmt.Errorf("loading controls: %w", err)
	}
	if len(loaded) == 0 {
		return nil, fmt.Errorf("no controls found in %s", opts.ControlsDir)
	}

	m := metrics.New()
	m.RegisterDBPool(opts.Store.Pool())
	b := bus.New()
	b.OnDrop = func(_ uuid.UUID, k bus.Kind) { m.RecordBusDrop(string(k)) }

	outbox := eventbus.NewOutbox(opts.Store.Pool())
	publisher := opts.EventPublisher
	if publisher == nil {
		publisher = eventbus.PublisherFunc(func(_ context.Context, _ string, _ []byte, _ map[string]string) error { return nil })
	}
	dispatcher, err := eventbus.NewDispatcher(outbox, publisher, opts.DispatcherConfig, eventbus.DispatcherMetrics{
		Published:   func(k string) { m.OutboxPublishedTotal.WithLabelValues(k).Inc() },
		Failed:      func(k string) { m.OutboxFailedTotal.WithLabelValues(k).Inc() },
		Dead:        func(k string) { m.OutboxDeadTotal.WithLabelValues(k).Inc() },
		PublishTime: func(s float64) { m.OutboxPublishDuration.Observe(s) },
		Lag:         func(s float64) { m.OutboxLagSeconds.Set(s) },
		Cleaned:     func(n int64) { m.OutboxCleanupDeletedTotal.Add(float64(n)) },
		TickError:   func(stage string, _ error) { m.OutboxTickErrorsTotal.WithLabelValues(stage).Inc() },
	})
	if err != nil {
		return nil, fmt.Errorf("event dispatcher: %w", err)
	}

	dispCtx, dispCancel := context.WithCancel(context.Background())
	go dispatcher.Run(dispCtx)

	idem := buildIdempotency(opts.RedisLimiter, m)

	rotator, err := auditpart.New(opts.Store, auditpart.Config{
		MonthsAhead:    3,
		Interval:       24 * time.Hour,
		JitterFraction: 0.1,
	}, auditpart.Metrics{
		Created: func(name string) { m.AuditPartitionsCreatedTotal.WithLabelValues(name).Inc() },
		Ensured: func(string) { m.AuditPartitionRotatorTicksTotal.Inc() },
		Failed:  func(error) { m.AuditPartitionRotatorErrorsTotal.Inc() },
	})
	if err != nil {
		dispCancel()
		return nil, fmt.Errorf("audit partition rotator: %w", err)
	}
	rotCtx, rotCancel := context.WithCancel(context.Background())
	go rotator.Run(rotCtx)

	return &Concord{
		Controls:           loaded,
		Config:             cfg,
		Store:              opts.Store,
		OperatorToken:      opts.OperatorToken,
		Version:            opts.Version,
		SessionTTL:         opts.SessionTTL,
		CORSAllowedOrigins: opts.CORSAllowedOrigins,
		bus:                b,
		metrics:            m,
		mailer:             mail.New(opts.SMTP),
		bg:                 bg.New(),
		tracing:            opts.Tracing,
		authLimits:         buildAuthLimits(opts.RedisLimiter, opts.LimiterFallbackTighten, m),
		pubLimits:          buildPublicLimits(opts.RedisLimiter, opts.LimiterFallbackTighten, m),
		outbox:             outbox,
		dispatcher:         dispatcher,
		dispCancel:         dispCancel,
		idempotency:        idem,
		auditRotator:       rotator,
		auditRotCancel:     rotCancel,
	}, nil
}

func buildIdempotency(rdb *redis.Client, m *metrics.Metrics) func(http.Handler) http.Handler {
	return idempotency.Middleware(idempotency.Config{
		Redis: rdb,
		OrgIDFn: func(r *http.Request) (string, bool) {
			if slug := r.PathValue("slug"); slug != "" {
				return slug, true
			}
			return "", false
		},
		OnRedisError: func(error) { m.IdempotencyRedisErrorsTotal.Inc() },
		OnHit:        func() { m.IdempotencyHitsTotal.Inc() },
		OnMismatch:   func() { m.IdempotencyMismatchTotal.Inc() },
		OnPending:    func() { m.IdempotencyPendingTotal.Inc() },
	})
}

type gateConfig struct {
	name string
	cfg  limiter.Config
}

var authGates = struct {
	loginIP, loginEmail, pwResetIP, pwConfirmIP, mfaSubmitIP gateConfig
}{
	loginIP:     gateConfig{"login_ip", limiter.Config{Rate: limiter.Every(2 * time.Second), Burst: 10}},
	loginEmail:  gateConfig{"login_email", limiter.Config{Rate: limiter.Every(6 * time.Second), Burst: 20}},
	pwResetIP:   gateConfig{"pw_reset_ip", limiter.Config{Rate: limiter.Every(6 * time.Second), Burst: 5}},
	pwConfirmIP: gateConfig{"pw_confirm_ip", limiter.Config{Rate: limiter.Every(2 * time.Second), Burst: 10}},
	mfaSubmitIP: gateConfig{"mfa_submit_ip", limiter.Config{Rate: limiter.Every(2 * time.Second), Burst: 10}},
}

var publicGates = struct {
	inviteAcceptIP gateConfig
}{
	inviteAcceptIP: gateConfig{"invite_accept_ip", limiter.Config{Rate: limiter.Every(2 * time.Second), Burst: 10}},
}

func buildAuthLimits(rdb *redis.Client, tighten float64, m *metrics.Metrics) auth.Limits {
	return auth.Limits{
		LoginIP:     buildBucket(authGates.loginIP, rdb, tighten, m),
		LoginEmail:  buildBucket(authGates.loginEmail, rdb, tighten, m),
		PWResetIP:   buildBucket(authGates.pwResetIP, rdb, tighten, m),
		PWConfirmIP: buildBucket(authGates.pwConfirmIP, rdb, tighten, m),
		MFASubmitIP: buildBucket(authGates.mfaSubmitIP, rdb, tighten, m),
	}
}

func buildPublicLimits(rdb *redis.Client, tighten float64, m *metrics.Metrics) public.Limits {
	return public.Limits{
		InviteAcceptIP: buildBucket(publicGates.inviteAcceptIP, rdb, tighten, m),
	}
}

func buildBucket(g gateConfig, rdb *redis.Client, tighten float64, m *metrics.Metrics) limiter.Bucket {
	if rdb == nil {
		return limiter.NewMemoryBucket(g.cfg)
	}
	if tighten <= 0 || tighten > 1 {
		tighten = 0.33
	}

	primary, err := limiter.NewRedisBucket(rdb, limiter.RedisBucketOptions{
		Config: g.cfg,
		Prefix: "concord:rl:" + g.name + ":",
	})
	if err != nil {
		return limiter.NewMemoryBucket(g.cfg)
	}

	fallbackCfg := limiter.Config{
		Rate:  limiter.PerSecond(float64(g.cfg.Rate) * tighten),
		Burst: int(float64(g.cfg.Burst) * tighten),
		TTL:   g.cfg.TTL,
	}
	if fallbackCfg.Burst < 1 {
		fallbackCfg.Burst = 1
	}
	fallback := limiter.NewMemoryBucket(fallbackCfg)

	fb, err := limiter.NewFailoverBucket(primary, fallback)
	if err != nil {
		return limiter.NewMemoryBucket(g.cfg)
	}
	gateName := g.name
	fb.OnPrimaryError = func(error) { m.RecordLimiterPrimaryError(gateName) }
	return fb
}

func applyDefaults(opts *Options) {
	if opts.ControlsDir == "" {
		opts.ControlsDir = "./controls"
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = "./concord.yaml"
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 24 * time.Hour
	}
}

func (c *Concord) Shutdown(ctx context.Context) error {
	if c.dispCancel != nil {
		c.dispCancel()
	}
	if c.auditRotCancel != nil {
		c.auditRotCancel()
	}
	return c.bg.Wait(ctx)
}

func (c *Concord) Bus() *bus.Bus { return c.bus }
