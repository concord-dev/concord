package operator

import (
	"encoding/json"
	"net/http"

	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

func (h *Handlers) CreateOrg(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" || body.Slug == "" {
		httpx.Error(w, http.StatusBadRequest, "name and slug are required")
		return
	}
	org, err := h.store.CreateOrganization(r.Context(), body.Name, body.Slug)
	if err != nil {
		httpx.Error(w, http.StatusConflict, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "org.create",
		OrgID:      &org.ID,
		TargetType: "organization",
		TargetID:   &org.ID,
		Details:    map[string]any{"name": org.Name, "slug": org.Slug},
	})
	httpx.JSON(w, http.StatusCreated, org)
}

func (h *Handlers) ListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.store.ListOrganizations(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, orgs)
}

func (h *Handlers) GetOrg(w http.ResponseWriter, r *http.Request) {
	org, ok := h.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	httpx.JSON(w, http.StatusOK, org)
}

func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	u, err := h.store.CreateUser(r.Context(), store.CreateUserParams{
		FirstName: body.FirstName, LastName: body.LastName,
		Email: body.Email, Password: body.Password,
	})
	if err != nil {
		httpx.Error(w, http.StatusConflict, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "user.create",
		TargetType: "user",
		TargetID:   &u.ID,
		Details:    map[string]any{"email": u.Email},
	})
	httpx.JSON(w, http.StatusCreated, u)
}

func (h *Handlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, users)
}

func (h *Handlers) ListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.store.ListRoles(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	type entry struct {
		store.Role
		Permissions []store.Permission `json:"permissions"`
	}
	out := make([]entry, 0, len(roles))
	for _, r0 := range roles {
		perms, err := h.store.ListRolePermissions(r.Context(), r0.ID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, entry{Role: r0, Permissions: perms})
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (h *Handlers) ListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.store.ListPermissions(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, perms)
}
