// Package server hosts Concord's HTTP API. It speaks two auth mechanisms:
//
//   - API tokens (Authorization: Bearer concord_...) for CI/CLI
//   - User sessions (Authorization: Bearer concord_sess_...) for the web
//     dashboard
//
// Both paths converge on a principal carrying the resolved org and (for
// session auth) the user. Per-endpoint permission checks consult the RBAC
// tables via Store.HasPermission.
//
// File layout:
//
//	server.go                  Concord struct + NewConcord + lifecycle
//	router.go                  Router() with the wired mux
//	middleware.go              requireAdmin/requireSession/requireOrgPerm
//	http_helpers.go            writeJSON, logging middleware
//	lookups.go                 lookupOrgBySlug, lookupUser, controlExists
//	handlers_public.go         /healthz, /version, /openapi.yaml, /docs
//	handlers_auth.go           /v1/auth/* and session-scoped /v1/me*
//	handlers_admin_orgs.go     /admin/v1/orgs, users, roles, permissions
//	handlers_admin_members.go  /admin/v1/orgs/{slug}/members/*
//	handlers_admin_tokens.go   /admin/v1/orgs/{slug}/tokens/*
//	handlers_org_controls.go   /v1/orgs/{slug}/me, frameworks, controls
//	handlers_org_runs.go       /v1/orgs/{slug}/check, findings, runs/*
//	handlers_org_events.go     /v1/orgs/{slug}/events (SSE)
//	handlers_org_overrides.go  /v1/orgs/{slug}/controls/{id}/overrides
//	handlers_org_schedule.go   /v1/orgs/{slug}/schedule
//	handlers_org_webhooks.go   /v1/orgs/{slug}/webhooks/*
//	worker.go, bus.go, scheduler.go, webhook_delivery.go (cross-cutting)
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
	bus       *Bus
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
	SessionTTL   time.Duration // default: 24h
	Worker       WorkerOpts
	Scheduler    SchedulerOpts
}

// NewConcord loads controls + config and wires the Store, worker, scheduler,
// and event bus. Returns an error when the controls directory is empty or
// the Store is missing.
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
		bus:        NewBus(),
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

// resolveRegistry returns the registry the caller supplied or builds a
// default one. Default + FixturesOnly is the local-dev mode.
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

// Shutdown stops the scheduler then drains the worker, in that order — so
// the scheduler can't enqueue new work after the worker queue is closing.
func (c *Concord) Shutdown(ctx context.Context) error {
	_ = c.scheduler.Shutdown(ctx)
	return c.worker.Shutdown(ctx)
}

// SchedulerForTest exposes the scheduler for tests that need to fire ticks manually.
func (c *Concord) SchedulerForTest() *Scheduler { return c.scheduler }

// Bus exposes the event bus to callers that subscribe (the SSE handler).
func (c *Concord) Bus() *Bus { return c.bus }
