// Package server hosts Concord's HTTP API. It speaks two auth mechanisms:
//
//   - API tokens (Authorization: Bearer concord_...) for CI/CLI
//   - User sessions (Authorization: Bearer concord_sess_...) for the web
//     dashboard
//
// Both converge on an authctx.Principal carrying the resolved org and (for
// session auth) the user. Per-endpoint permission checks consult the RBAC
// tables via Store.HasPermission.
//
// File layout:
//
//	server.go              Concord struct + NewConcord + lifecycle
//	router.go              Router() with the wired mux
//	worker.go              In-process run worker pool
//	scheduler.go           Cron-driven schedule poller
//	webhook_delivery.go    Outbound webhook signing + delivery
//	handlers/<group>/      Per-domain handler subpackages
//	middleware/            RequireAdmin / RequireSession / RequireOrgPerm
//	httpx/                 JSON + Error + Logging helpers
//	authctx/               Principal + session context types
//	bus/                   In-process event bus (SSE fan-out)
//	cronx/                 Cron expression parsing
//	openapi/               Embedded API spec
package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/concord-dev/concord/internal/config"
	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/store"
)

// Concord bundles in-memory state + Store.
type Concord struct {
	Controls   []controls.Loaded
	Config     *config.Config
	Registry   *evidence.Registry
	Store      *store.Store
	AdminToken string
	Version    string
	SessionTTL time.Duration

	worker    *Worker
	bus       *bus.Bus
	scheduler *Scheduler
	mu        sync.Mutex
}

// Options is the construction surface for cmd/server.
type Options struct {
	ControlsDir  string
	ConfigPath   string
	FixturesOnly bool
	Registry     *evidence.Registry
	Store        *store.Store
	AdminToken   string
	Version      string
	SessionTTL   time.Duration
	Worker       WorkerOpts
	Scheduler    SchedulerOpts
}

// NewConcord loads controls + config and wires the Store, worker, scheduler,
// and event bus.
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

	c := &Concord{
		Controls:   loaded,
		Config:     cfg,
		Registry:   resolveRegistry(opts),
		Store:      opts.Store,
		AdminToken: opts.AdminToken,
		Version:    opts.Version,
		SessionTTL: opts.SessionTTL,
		bus:        bus.New(),
	}
	c.worker = NewWorker(c, opts.Worker)
	c.worker.Start()
	c.scheduler = NewScheduler(c, opts.Scheduler)
	c.scheduler.Start()
	return c, nil
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

// resolveRegistry returns the registry the caller supplied or builds a default
// one. Default + FixturesOnly is the local-dev mode.
func resolveRegistry(opts Options) *evidence.Registry {
	if opts.Registry != nil {
		return opts.Registry
	}
	reg := evidence.NewRegistry()
	if opts.FixturesOnly {
		reg.SetFixturesOnly(true)
	}
	return reg
}

// Shutdown stops the scheduler then drains the worker, in that order — so the
// scheduler can't enqueue new work after the worker queue is closing.
func (c *Concord) Shutdown(ctx context.Context) error {
	_ = c.scheduler.Shutdown(ctx)
	return c.worker.Shutdown(ctx)
}

// SchedulerForTest exposes the scheduler for tests that need to fire ticks manually.
func (c *Concord) SchedulerForTest() *Scheduler { return c.scheduler }

// Bus exposes the event bus to callers (the SSE handler).
func (c *Concord) Bus() *bus.Bus { return c.bus }
