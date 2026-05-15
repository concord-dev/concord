// Package org hosts every /v1/orgs/{slug}/* endpoint. Each request reaches a
// handler only after middleware.RequireOrgPerm has authenticated the caller
// and injected the resolved org + caller identity via authctx.
package org

import (
	"strings"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/store"
)

// Enqueuer is the worker contract org handlers depend on. Defined here (not in
// the worker package) so the handler subpackage takes the smaller surface.
type Enqueuer interface {
	Enqueue(orgID, runID uuid.UUID) error
}

// Handlers bundles dependencies for the org route group.
type Handlers struct {
	store    *store.Store
	controls []controls.Loaded
	worker   Enqueuer
	bus      *bus.Bus
}

// New constructs Handlers wired to the supplied infrastructure.
func New(s *store.Store, ctrls []controls.Loaded, w Enqueuer, b *bus.Bus) *Handlers {
	return &Handlers{store: s, controls: ctrls, worker: w, bus: b}
}

// controlExists is a cheap membership check against the loaded controls library.
func (h *Handlers) controlExists(id string) bool {
	target := strings.ToLower(id)
	for _, l := range h.controls {
		if strings.ToLower(l.Control.Metadata.ID) == target {
			return true
		}
	}
	return false
}
