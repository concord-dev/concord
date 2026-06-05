package operator

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

type Handlers struct {
	store *store.Store
}

func New(s *store.Store) *Handlers { return &Handlers{store: s} }

func (h *Handlers) audit(r *http.Request, p store.RecordAuditParams) {
	p.ActorKind = store.AuditActorOperator
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
