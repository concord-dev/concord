// Package org hosts every /v1/orgs/{slug}/* endpoint. Each request reaches a
// handler only after middleware.RequireOrgPerm has authenticated the caller
// and injected the resolved org + caller identity via authctx.
package org

import (
	"net/http"
	"strings"

	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/notify/mail"
	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/bg"
	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// Broadcaster is the side-effect surface SubmitRun needs after a run lands:
//   - RunCompleted publishes the run.completed event + fires webhooks
//   - DriftDetected publishes the control.drifted event + fires webhooks
//     (called only when there's at least one transition)
// Injected as a struct of funcs rather than a concrete type so the org
// handler stays decoupled from webhook delivery internals.
type Broadcaster struct {
	RunCompleted  func(run store.Run, summary []byte)
	DriftDetected func(run store.Run, transitions []bus.Transition)
}

// Handlers bundles dependencies for the org route group.
type Handlers struct {
	store     *store.Store
	controls  []controls.Loaded
	bus       *bus.Bus
	broadcast Broadcaster
	mailer    mail.Mailer
	bg        *bg.Runner
}

// New constructs Handlers wired to the supplied infrastructure. A zero
// Broadcaster is filled with no-op funcs so SubmitRun never nil-deref's
// in tests that don't care about side-effects. Mailer may be nil; the
// invitation handler degrades to logging the accept URL when it is.
// runner may be nil in tests; production wires the shared *bg.Runner
// from Concord so graceful shutdown can drain in-flight invitation
// emails before the process exits.
func New(s *store.Store, ctrls []controls.Loaded, b *bus.Bus, broadcast Broadcaster, mailer mail.Mailer, runner *bg.Runner) *Handlers {
	if broadcast.RunCompleted == nil {
		broadcast.RunCompleted = func(store.Run, []byte) {}
	}
	if broadcast.DriftDetected == nil {
		broadcast.DriftDetected = func(store.Run, []bus.Transition) {}
	}
	return &Handlers{store: s, controls: ctrls, bus: b, broadcast: broadcast, mailer: mailer, bg: runner}
}

// goAsync runs fn on the tracked background runner when one is wired,
// otherwise spawns an untracked goroutine. Same fallback pattern as the
// auth handler — production wires a runner; tests may not.
func (h *Handlers) goAsync(fn func()) {
	if h.bg != nil {
		h.bg.Go(fn)
		return
	}
	go fn()
}

// audit fills in the actor (from the authctx Principal) and request-scoped
// forensic fields, then delegates to store.RecordAudit. ActorKind is
// inferred: a session-authenticated request carries actor_user_id; an
// API-token request carries actor_token_id. Best-effort — failures are
// logged but never returned to the caller.
func (h *Handlers) audit(r *http.Request, p store.RecordAuditParams) {
	if p.ActorKind == "" {
		if prin, ok := authctx.PrincipalFrom(r.Context()); ok {
			switch {
			case prin.UserID != nil:
				p.ActorKind = store.AuditActorUser
				p.ActorUserID = prin.UserID
			case prin.TokenID != nil:
				p.ActorKind = store.AuditActorToken
				p.ActorTokenID = prin.TokenID
			default:
				p.ActorKind = store.AuditActorSystem
			}
			if p.OrgID == nil {
				oid := prin.Org.ID
				p.OrgID = &oid
			}
		} else {
			p.ActorKind = store.AuditActorSystem
		}
	}
	if p.IP == "" {
		p.IP = httpx.ClientIP(r)
	}
	if p.UserAgent == "" {
		p.UserAgent = r.UserAgent()
	}
	if p.RequestID == "" {
		p.RequestID = logx.RequestID(r.Context())
	}
	h.store.RecordAudit(r.Context(), p)
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
