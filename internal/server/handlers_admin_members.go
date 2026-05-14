package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/store"
)

// handleAdminAddMember attaches a user to an org with one or more roles.
// Role names are validated up-front so partial inserts can't happen.
func (c *Concord) handleAdminAddMember(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	var body struct {
		UserID string   `json:"user_id"`
		Email  string   `json:"email"`
		Roles  []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(body.Roles) == 0 {
		writeError(w, http.StatusBadRequest, "at least one role is required")
		return
	}
	user, ok := c.lookupUser(w, r, body.UserID, body.Email)
	if !ok {
		return
	}
	roleIDs, ok := c.resolveRoleNames(w, r, body.Roles)
	if !ok {
		return
	}
	for _, rid := range roleIDs {
		if err := c.Store.AssignRole(r.Context(), user.ID, org.ID, rid); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"user":  user,
		"org":   org,
		"roles": body.Roles,
	})
}

// resolveRoleNames maps role-name strings to UUIDs, surfacing 400s for
// unknown roles before the caller touches the membership table.
func (c *Concord) resolveRoleNames(w http.ResponseWriter, r *http.Request, names []string) ([]uuid.UUID, bool) {
	out := make([]uuid.UUID, 0, len(names))
	for _, name := range names {
		role, err := c.Store.GetRoleByName(r.Context(), name)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "unknown role "+name)
			return nil, false
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return nil, false
		}
		out = append(out, role.ID)
	}
	return out, true
}

func (c *Concord) handleAdminListMembers(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	members, err := c.Store.ListOrgMembers(r.Context(), org.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, members)
}

func (c *Concord) handleAdminRemoveMember(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	userID, err := uuid.Parse(r.PathValue("userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if err := c.Store.RemoveUserFromOrg(r.Context(), userID, org.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "membership not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
