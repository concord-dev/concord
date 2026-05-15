package admin

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// AddMember attaches a user to an org with one or more roles. Role names are
// validated up-front so partial inserts can't happen.
func (h *Handlers) AddMember(w http.ResponseWriter, r *http.Request) {
	org, ok := h.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	var body struct {
		UserID string   `json:"user_id"`
		Email  string   `json:"email"`
		Roles  []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(body.Roles) == 0 {
		httpx.Error(w, http.StatusBadRequest, "at least one role is required")
		return
	}
	user, ok := h.lookupUser(w, r, body.UserID, body.Email)
	if !ok {
		return
	}
	roleIDs, ok := h.resolveRoleNames(w, r, body.Roles)
	if !ok {
		return
	}
	for _, rid := range roleIDs {
		if err := h.store.AssignRole(r.Context(), user.ID, org.ID, rid); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"user":  user,
		"org":   org,
		"roles": body.Roles,
	})
}

func (h *Handlers) resolveRoleNames(w http.ResponseWriter, r *http.Request, names []string) ([]uuid.UUID, bool) {
	out := make([]uuid.UUID, 0, len(names))
	for _, name := range names {
		role, err := h.store.GetRoleByName(r.Context(), name)
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusBadRequest, "unknown role "+name)
			return nil, false
		}
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return nil, false
		}
		out = append(out, role.ID)
	}
	return out, true
}

func (h *Handlers) ListMembers(w http.ResponseWriter, r *http.Request) {
	org, ok := h.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	members, err := h.store.ListOrgMembers(r.Context(), org.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, members)
}

func (h *Handlers) RemoveMember(w http.ResponseWriter, r *http.Request) {
	org, ok := h.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	userID, err := uuid.Parse(r.PathValue("userID"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if err := h.store.RemoveUserFromOrg(r.Context(), userID, org.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "membership not found")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
