// Package server hosts Concord's HTTP API. It speaks two auth mechanisms:
//
//   - API tokens (Authorization: Bearer concord_...) for CI/CLI agents
//   - User sessions (Authorization: Bearer concord_sess_...) for the web
//     dashboard
//
// Both converge on an authctx.Principal carrying the resolved org and (for
// session auth) the user. Per-endpoint permission checks consult the RBAC
// tables via Store.HasPermission.
//
// The server is a thin findings receiver: agents (the `concord` CLI) run
// scans on the customer's own infrastructure with the customer's own
// credentials, and POST completed runs to /v1/orgs/{slug}/runs. Concord
// stores findings, fans out events (SSE + webhooks), and renders read
// surfaces. It never holds customer cloud credentials.
//
// File layout:
//
//	server.go              Concord struct + NewConcord + lifecycle
//	router.go              Router() with the wired mux
//	webhook_delivery.go    Outbound webhook signing + delivery + broadcast
//	handlers/<group>/      Per-domain handler subpackages
//	middleware/            RequireOperator / RequireSession / RequireOrgPerm
//	httpx/                 JSON + Error + Logging helpers
//	authctx/               Principal + session context types
//	bus/                   In-process event bus (SSE fan-out)
//	openapi/               Embedded API spec
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
	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/server/handlers/auth"
	"github.com/concord-dev/concord/internal/server/handlers/public"
	"github.com/concord-dev/concord/internal/server/idempotency"
	"github.com/concord-dev/concord/internal/server/limiter"
	"github.com/concord-dev/concord/internal/server/metrics"
	"github.com/concord-dev/concord/internal/store"
)

// Concord bundles in-memory state + Store.
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

	// outbox is the durable event pipe to Kafka. Handlers write here in
	// the same SQL tx as their state change (transactional outbox
	// pattern); the dispatcher polls and ships. Always non-nil — when
	// Kafka is not configured the publisher is a no-op recorder so rows
	// still accrue durably and can be replayed once Kafka comes online.
	outbox     *eventbus.Outbox
	dispatcher *eventbus.Dispatcher
	dispCancel context.CancelFunc // stops the dispatcher loop in Shutdown

	// idempotency is the Redis-backed dedupe middleware (Phase 5). nil
	// when no Redis client was wired, in which case the middleware is
	// a no-op pass-through.
	idempotency func(http.Handler) http.Handler
}

// Options is the construction surface for cmd/server.
type Options struct {
	ControlsDir        string
	ConfigPath         string
	Store              *store.Store
	OperatorToken      string
	Version            string
	SessionTTL         time.Duration
	CORSAllowedOrigins []string
	// SMTP configures outbound mail. A zero value yields a LogMailer that
	// just prints the message body — fine for local dev, never reaches a
	// real inbox. Set Host (and From) to wire a real relay.
	SMTP mail.Config

	// Tracing, when non-nil, is the OpenTelemetry provider the server
	// uses for distributed tracing. Wire via otelx.Init from cmd/server.
	// Leave nil to disable tracing entirely (handlers still compile —
	// the global otel.Tracer fallback is a no-op).
	Tracing *otelx.Provider

	// RedisLimiter, when non-nil, switches the rate-limiter from per-pod
	// in-memory buckets to fleet-wide Redis-backed buckets wrapped in a
	// FailoverBucket. The fallback is a tightened in-memory bucket so a
	// Redis outage degrades gracefully rather than 503'ing auth, but
	// without amplifying an attack to N× the configured budget. Nil
	// keeps the historical per-pod behaviour (fine for single-replica
	// deploys and tests).
	RedisLimiter *redis.Client

	// LimiterFallbackTighten is the multiplier applied to Rate and Burst
	// when constructing the in-memory fallback inside a FailoverBucket.
	// 0.33 (the default) means each pod's fallback budget is ~1/3 the
	// shared budget — for the canonical 3-replica deploy that keeps the
	// fleet-wide ceiling at the configured rate during a Redis outage.
	// Operators with more replicas should pass a smaller value.
	LimiterFallbackTighten float64

	// EventPublisher is the Kafka-or-equivalent sink the outbox
	// dispatcher ships rows to. When nil, NewConcord wires a no-op
	// publisher that returns nil — rows still get marked published so
	// the queue drains; nothing reaches a broker. This is the dev /
	// "Kafka not configured yet" path.
	EventPublisher eventbus.Publisher

	// DispatcherConfig overrides the outbox dispatcher's defaults
	// (poll interval, batch size, max attempts, …). Zero values fall
	// back to NewDispatcher's defaults.
	DispatcherConfig eventbus.DispatcherConfig
}

// NewConcord loads controls + config and wires the Store and event bus.
// No background goroutines — runs arrive from agents over HTTP.
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
		// No Kafka wired — rows still accrue durably; a no-op
		// publisher just returns nil so the dispatcher marks them
		// published and the queue drains. Switch to a real publisher
		// later and the in-flight rows ship on the next tick.
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
	}, nil
}

// buildIdempotency constructs the Idempotency-Key middleware. When no
// Redis client is wired the middleware degrades to a pass-through —
// Phase 5 leaves the local-dev path unaffected. The org slug is
// extracted from r.PathValue("slug") because the mux fills it before
// the middleware runs (we mount idempotency INSIDE the per-route
// permission gate).
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

// gateConfig pairs a gate name (used in metric labels + Redis key prefix)
// with the desired token-bucket policy. cmd/server uses the same shape
// for every gate so a future per-gate flag override has a place to land.
type gateConfig struct {
	name string
	cfg  limiter.Config
}

// authGates is the production rate-limit policy for /v1/auth/*. The
// burst sizes are chosen to be lenient enough for a legit user fumbling
// a password a few times, but tight enough to stop credential-stuffing
// and password-spray tools that hit the endpoint thousands of times
// per minute.
//
//	login_ip        30 req/min, burst 10  — per source IP
//	login_email     10 req/min, burst 20  — per (lowercased) email
//	pw_reset_ip     10 req/min, burst 5   — request endpoint
//	pw_confirm_ip   30 req/min, burst 10  — confirm endpoint (token guess attempts)
//	mfa_submit_ip   30 req/min, burst 10  — second-leg login (TOTP / recovery code)
var authGates = struct {
	loginIP, loginEmail, pwResetIP, pwConfirmIP, mfaSubmitIP gateConfig
}{
	loginIP:     gateConfig{"login_ip", limiter.Config{Rate: limiter.Every(2 * time.Second), Burst: 10}},
	loginEmail:  gateConfig{"login_email", limiter.Config{Rate: limiter.Every(6 * time.Second), Burst: 20}},
	pwResetIP:   gateConfig{"pw_reset_ip", limiter.Config{Rate: limiter.Every(6 * time.Second), Burst: 5}},
	pwConfirmIP: gateConfig{"pw_confirm_ip", limiter.Config{Rate: limiter.Every(2 * time.Second), Burst: 10}},
	mfaSubmitIP: gateConfig{"mfa_submit_ip", limiter.Config{Rate: limiter.Every(2 * time.Second), Burst: 10}},
}

// publicGates is the production rate-limit policy for the unauthenticated
// public endpoints. AcceptInvitation accepts a token in the body;
// without a limit, an attacker can grind through tokens.
//
//	invite_accept_ip 30 req/min, burst 10  — per source IP
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

// buildBucket returns a MemoryBucket when no Redis client is wired, or a
// FailoverBucket(RedisBucket, tightenedMemoryBucket) when one is. The
// tightenedMemoryBucket clamps Rate and Burst by `tighten` (default 0.33)
// so a sustained Redis outage can't be used to amplify an attack across
// pods — each pod's fallback budget is a fraction of the shared budget.
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
		// Misconfiguration — fall back to memory rather than panicking
		// at startup. metrics is best-effort here.
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

// applyDefaults fills in sensible Options defaults so callers can pass a
// near-empty Options struct in tests.
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

// Shutdown blocks until every tracked background goroutine (webhook
// deliveries, transactional emails, bus-drop accounting) finishes, or
// ctx expires — whichever comes first. After this returns the Concord
// instance refuses new background work; callers should have already
// drained the HTTP server (via *http.Server.Shutdown) so handlers can't
// still be spawning work.
//
// Returns ctx.Err() (typically context.DeadlineExceeded) when the drain
// timed out. Operators reading that error should treat it as "some
// notifications may not have reached their destinations" and decide
// whether to re-fire or live with the loss.
func (c *Concord) Shutdown(ctx context.Context) error {
	// Stop the dispatcher first so it doesn't keep claiming rows during
	// the bg drain. Then wait for in-flight tracked goroutines (webhook
	// delivery, async email). The dispatcher's Run goroutine notices
	// dispCancel and exits its select; we don't wait on it explicitly
	// because the only side effects are completed Kafka publishes
	// (already commited to the DB) — partially-acked publishes will be
	// re-claimed on the next process start.
	if c.dispCancel != nil {
		c.dispCancel()
	}
	return c.bg.Wait(ctx)
}

// Bus exposes the event bus to callers (the SSE handler).
func (c *Concord) Bus() *bus.Bus { return c.bus }
