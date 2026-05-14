package server

import (
	"encoding/json"
	"net/http"

	"github.com/concord-dev/concord/internal/store"
)

// handleAdminCreateOrg creates an organization. Slug must be unique;
// duplicates surface as 409.
func (c *Concord) handleAdminCreateOrg(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" || body.Slug == "" {
		writeError(w, http.StatusBadRequest, "name and slug are required")
		return
	}
	org, err := c.Store.CreateOrganization(r.Context(), body.Name, body.Slug)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, org)
}

func (c *Concord) handleAdminListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := c.Store.ListOrganizations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, orgs)
}

func (c *Concord) handleAdminGetOrg(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, org)
}

// handleAdminCreateUser creates a user. Password is optional — invite-pending
// users can be created without one.
func (c *Concord) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	u, err := c.Store.CreateUser(r.Context(), store.CreateUserParams{
		FirstName: body.FirstName, LastName: body.LastName,
		Email: body.Email, Password: body.Password,
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (c *Concord) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := c.Store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, users)
}

// handleAdminListRoles returns every role with its permission bundle so a
// UI can render the canonical RBAC matrix.
func (c *Concord) handleAdminListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := c.Store.ListRoles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type entry struct {
		store.Role
		Permissions []store.Permission `json:"permissions"`
	}
	out := make([]entry, 0, len(roles))
	for _, r0 := range roles {
		perms, err := c.Store.ListRolePermissions(r.Context(), r0.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, entry{Role: r0, Permissions: perms})
	}
	writeJSON(w, http.StatusOK, out)
}

func (c *Concord) handleAdminListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := c.Store.ListPermissions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, perms)
}
