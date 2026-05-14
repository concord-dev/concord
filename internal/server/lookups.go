package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/store"
)

// lookupOrgBySlug fetches an org by slug and writes a 404/500 if absent.
// Returns ok=false when the handler should not continue.
func (c *Concord) lookupOrgBySlug(w http.ResponseWriter, r *http.Request, slug string) (store.Organization, bool) {
	org, err := c.Store.GetOrganizationBySlug(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no organization with slug "+slug)
		return store.Organization{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return store.Organization{}, false
	}
	return org, true
}

// lookupUser accepts either a UUID or an email and returns the matching user.
// Used by membership endpoints so operators can attach humans by email.
func (c *Concord) lookupUser(w http.ResponseWriter, r *http.Request, idStr, email string) (store.User, bool) {
	if idStr != "" {
		id, err := uuid.Parse(idStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid user_id")
			return store.User{}, false
		}
		u, err := c.Store.GetUserByID(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return store.User{}, false
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return store.User{}, false
		}
		return u, true
	}
	if email == "" {
		writeError(w, http.StatusBadRequest, "either user_id or email is required")
		return store.User{}, false
	}
	u, err := c.Store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return store.User{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return store.User{}, false
	}
	return u, true
}

// controlExists is a cheap membership check against the loaded controls
// library so PUT/GET against unknown control ids return a clear 404 rather
// than persisting a row no policy will ever consume.
func (c *Concord) controlExists(id string) bool {
	target := strings.ToLower(id)
	for _, l := range c.Controls {
		if strings.ToLower(l.Control.Metadata.ID) == target {
			return true
		}
	}
	return false
}
