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

type Broadcaster struct {
	RunCompleted  func(run store.Run, summary []byte)
	DriftDetected func(run store.Run, transitions []bus.Transition)
}

type Handlers struct {
	store     *store.Store
	controls  []controls.Loaded
	bus       *bus.Bus
	broadcast Broadcaster
	mailer    mail.Mailer
	bg        *bg.Runner
}

func New(s *store.Store, ctrls []controls.Loaded, b *bus.Bus, broadcast Broadcaster, mailer mail.Mailer, runner *bg.Runner) *Handlers {
	if broadcast.RunCompleted == nil {
		broadcast.RunCompleted = func(store.Run, []byte) {}
	}
	if broadcast.DriftDetected == nil {
		broadcast.DriftDetected = func(store.Run, []bus.Transition) {}
	}
	return &Handlers{store: s, controls: ctrls, bus: b, broadcast: broadcast, mailer: mailer, bg: runner}
}

func (h *Handlers) goAsync(fn func()) {
	if h.bg != nil {
		h.bg.Go(fn)
		return
	}
	go fn()
}

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

func (h *Handlers) controlExists(id string) bool {
	target := strings.ToLower(id)
	for _, l := range h.controls {
		if strings.ToLower(l.Control.Metadata.ID) == target {
			return true
		}
	}
	return false
}
