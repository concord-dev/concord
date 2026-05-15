// Package org hosts every /v1/orgs/{slug}/* endpoint. Each request reaches a
// handler only after middleware.RequireOrgPerm has authenticated the caller
// and injected the resolved org + caller identity via authctx.
package org

import (
	"strings"

	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/store"
)

// Broadcaster is the side-effect surface SubmitRun needs after a run lands:
// publish a run.completed event on the in-process bus AND fire outbound
// webhooks. Injected as a func rather than concrete type so the org handler
// stays decoupled from webhook delivery internals.
type Broadcaster func(run store.Run, summary []byte)

// Handlers bundles dependencies for the org route group.
type Handlers struct {
	store     *store.Store
	controls  []controls.Loaded
	bus       *bus.Bus
	broadcast Broadcaster
}

// New constructs Handlers wired to the supplied infrastructure.
func New(s *store.Store, ctrls []controls.Loaded, b *bus.Bus, broadcast Broadcaster) *Handlers {
	if broadcast == nil {
		// No-op default so SubmitRun never nil-deref's in tests that don't
		// care about side-effects.
		broadcast = func(store.Run, []byte) {}
	}
	return &Handlers{store: s, controls: ctrls, bus: b, broadcast: broadcast}
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
