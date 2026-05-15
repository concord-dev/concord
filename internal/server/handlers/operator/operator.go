// Package operator hosts every /operator/v1/* endpoint, the Concord SaaS
// operator's back-door for provisioning tenants. All routes are gated by
// middleware.RequireOperator at mount time; nothing in this package re-checks
// the operator token.
package operator

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// Handlers bundles dependencies for the operator route group.
type Handlers struct {
	store *store.Store
}

// New constructs Handlers with the given Store.
func New(s *store.Store) *Handlers { return &Handlers{store: s} }

// audit records an operator-actor event. Operator events carry actor_kind
// "operator" with both ID columns NULL — the operator token is a SaaS-
// platform principal, not a user row. Same best-effort semantics as the
// auth-handler audit helper.
func (h *Handlers) audit(r *http.Request, p store.RecordAuditParams) {
	p.ActorKind = store.AuditActorOperator
	if p.IP == "" {
		p.IP = clientIP(r)
	}
	if p.UserAgent == "" {
		p.UserAgent = r.UserAgent()
	}
	if p.RequestID == "" {
		p.RequestID = logx.RequestID(r.Context())
	}
	h.store.RecordAudit(r.Context(), p)
}

// clientIP mirrors the auth-package helper (same shape, separate copy to
// keep the operator subpackage free of cross-handler imports).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// lookupOrgBySlug resolves an org by slug and writes 404/500 on failure.
func (h *Handlers) lookupOrgBySlug(w http.ResponseWriter, r *http.Request, slug string) (store.Organization, bool) {
	org, err := h.store.GetOrganizationBySlug(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "no organization with slug "+slug)
		return store.Organization{}, false
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return store.Organization{}, false
	}
	return org, true
}

// lookupUser accepts either a UUID or an email and returns the matching user.
func (h *Handlers) lookupUser(w http.ResponseWriter, r *http.Request, idStr, email string) (store.User, bool) {
	if idStr != "" {
		id, err := uuid.Parse(idStr)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid user_id")
			return store.User{}, false
		}
		u, err := h.store.GetUserByID(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "user not found")
			return store.User{}, false
		}
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return store.User{}, false
		}
		return u, true
	}
	if email == "" {
		httpx.Error(w, http.StatusBadRequest, "either user_id or email is required")
		return store.User{}, false
	}
	u, err := h.store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "user not found")
		return store.User{}, false
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return store.User{}, false
	}
	return u, true
}
