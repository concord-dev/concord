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
	"sync"
	"time"

	"github.com/google/uuid"

	"golang.org/x/time/rate"

	"github.com/concord-dev/concord/internal/config"
	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/notify/mail"
	"github.com/concord-dev/concord/internal/otelx"
	"github.com/concord-dev/concord/internal/server/bg"
	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/server/handlers/auth"
	"github.com/concord-dev/concord/internal/server/handlers/public"
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

	bus         *bus.Bus
	metrics     *metrics.Metrics
	mailer      mail.Mailer
	bg          *bg.Runner
	tracing     *otelx.Provider
	authLimits  auth.Limits
	pubLimits   public.Limits
	mu          sync.Mutex
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
}

// NewConcord loads controls + config and wires the Store and event bus.
// No background goroutines — runs arrive from agents over HTTP.
func NewConcord(opts Options) (*Concord, error) {
	if opts.Store == nil {
		return nil, errors.New("Store is required")
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
		authLimits:         defaultAuthLimits(),
		pubLimits:          defaultPublicLimits(),
	}, nil
}

// Mailer exposes the configured mail.Mailer so router-wired handlers can
// inject it. Returns the LogMailer fallback when SMTP is unconfigured —
// callers never need to nil-check.
func (c *Concord) Mailer() mail.Mailer { return c.mailer }

// defaultAuthLimits is the production rate-limit policy for /v1/auth/*. The
// burst sizes are chosen to be lenient enough for a legit user fumbling a
// password a few times, but tight enough to stop credential-stuffing and
// password-spray tools that hit the endpoint thousands of times per minute.
//
//	LoginIP       30 req/min, burst 10  — per source IP
//	LoginEmail    10 req/min, burst 20  — per (lowercased) email
//	PWResetIP     10 req/min, burst 5   — request endpoint
//	PWConfirmIP   30 req/min, burst 10  — confirm endpoint (token guess attempts)
//	MFASubmitIP   30 req/min, burst 10  — second-leg login (TOTP / recovery code)
func defaultAuthLimits() auth.Limits {
	return auth.Limits{
		LoginIP:     limiter.NewBucket(limiter.Config{Rate: rate.Every(2 * time.Second), Burst: 10}),
		LoginEmail:  limiter.NewBucket(limiter.Config{Rate: rate.Every(6 * time.Second), Burst: 20}),
		PWResetIP:   limiter.NewBucket(limiter.Config{Rate: rate.Every(6 * time.Second), Burst: 5}),
		PWConfirmIP: limiter.NewBucket(limiter.Config{Rate: rate.Every(2 * time.Second), Burst: 10}),
		MFASubmitIP: limiter.NewBucket(limiter.Config{Rate: rate.Every(2 * time.Second), Burst: 10}),
	}
}

// defaultPublicLimits is the production rate-limit policy for the
// unauthenticated public endpoints. AcceptInvitation accepts a token in
// the body; without a limit, an attacker can grind through tokens.
//
//	InviteAcceptIP 30 req/min, burst 10  — per source IP
func defaultPublicLimits() public.Limits {
	return public.Limits{
		InviteAcceptIP: limiter.NewBucket(limiter.Config{Rate: rate.Every(2 * time.Second), Burst: 10}),
	}
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
	return c.bg.Wait(ctx)
}

// Bus exposes the event bus to callers (the SSE handler).
func (c *Concord) Bus() *bus.Bus { return c.bus }

// Metrics exposes the Prometheus instrumentation. The router pulls .Handler()
// off this for /metrics; domain code uses it via the recorder methods on
// metrics.Metrics.
func (c *Concord) Metrics() *metrics.Metrics { return c.metrics }
