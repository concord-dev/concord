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

	"github.com/concord-dev/concord/internal/config"
	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/server/bus"
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

	bus     *bus.Bus
	metrics *metrics.Metrics
	mu      sync.Mutex
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
	}, nil
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

// Shutdown is a no-op today (no background workers to drain) but kept so
// cmd/server can call it during signal handling without conditionals. In
// the future it'll cancel any long-running webhook deliveries in flight.
func (c *Concord) Shutdown(ctx context.Context) error {
	_ = ctx
	return nil
}

// Bus exposes the event bus to callers (the SSE handler).
func (c *Concord) Bus() *bus.Bus { return c.bus }

// Metrics exposes the Prometheus instrumentation. The router pulls .Handler()
// off this for /metrics; domain code uses it via the recorder methods on
// metrics.Metrics.
func (c *Concord) Metrics() *metrics.Metrics { return c.metrics }
