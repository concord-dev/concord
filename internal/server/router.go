package server

import "net/http"

// Router returns the fully wired HTTP handler. The mount order is:
//
//  1. Public routes (no auth).
//  2. Auth lifecycle (POST /v1/auth/{login,logout}).
//  3. Admin (CONCORD_ADMIN_TOKEN required).
//  4. Session-only endpoints (current user, list orgs).
//  5. Org-scoped API (Bearer API token OR Bearer session token), each route
//     gated by a specific RBAC permission via requireOrgPerm.
//
// The whole tree is wrapped in the logging middleware before being returned.
func (c *Concord) Router() http.Handler {
	mux := http.NewServeMux()
	c.mountPublic(mux)
	c.mountAuth(mux)
	c.mountAdmin(mux)
	c.mountSession(mux)
	c.mountOrgAPI(mux)
	return logging(mux)
}

func (c *Concord) mountPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", c.handleHealth)
	mux.HandleFunc("GET /version", c.handleVersion)
	mux.HandleFunc("GET /openapi.yaml", c.handleOpenAPI)
	mux.HandleFunc("GET /docs", c.handleDocs)
}

func (c *Concord) mountAuth(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/login", c.handleLogin)
	mux.Handle("POST /v1/auth/logout", c.requireSession(http.HandlerFunc(c.handleLogout)))
}

func (c *Concord) mountAdmin(mux *http.ServeMux) {
	admin := c.requireAdmin

	mux.Handle("POST /admin/v1/orgs", admin(http.HandlerFunc(c.handleAdminCreateOrg)))
	mux.Handle("GET /admin/v1/orgs", admin(http.HandlerFunc(c.handleAdminListOrgs)))
	mux.Handle("GET /admin/v1/orgs/{slug}", admin(http.HandlerFunc(c.handleAdminGetOrg)))

	mux.Handle("POST /admin/v1/orgs/{slug}/tokens", admin(http.HandlerFunc(c.handleAdminCreateToken)))
	mux.Handle("GET /admin/v1/orgs/{slug}/tokens", admin(http.HandlerFunc(c.handleAdminListTokens)))
	mux.Handle("DELETE /admin/v1/orgs/{slug}/tokens/{tokenID}", admin(http.HandlerFunc(c.handleAdminRevokeToken)))

	mux.Handle("POST /admin/v1/orgs/{slug}/members", admin(http.HandlerFunc(c.handleAdminAddMember)))
	mux.Handle("GET /admin/v1/orgs/{slug}/members", admin(http.HandlerFunc(c.handleAdminListMembers)))
	mux.Handle("DELETE /admin/v1/orgs/{slug}/members/{userID}", admin(http.HandlerFunc(c.handleAdminRemoveMember)))

	mux.Handle("POST /admin/v1/users", admin(http.HandlerFunc(c.handleAdminCreateUser)))
	mux.Handle("GET /admin/v1/users", admin(http.HandlerFunc(c.handleAdminListUsers)))
	mux.Handle("GET /admin/v1/roles", admin(http.HandlerFunc(c.handleAdminListRoles)))
	mux.Handle("GET /admin/v1/permissions", admin(http.HandlerFunc(c.handleAdminListPermissions)))
}

func (c *Concord) mountSession(mux *http.ServeMux) {
	mux.Handle("GET /v1/me", c.requireSession(http.HandlerFunc(c.handleSessionMe)))
	mux.Handle("GET /v1/me/orgs", c.requireSession(http.HandlerFunc(c.handleSessionOrgs)))
}

func (c *Concord) mountOrgAPI(mux *http.ServeMux) {
	read := c.requireOrgPerm("controls:read")
	runRead := c.requireOrgPerm("runs:read")
	runCreate := c.requireOrgPerm("runs:create")
	override := c.requireOrgPerm("controls:override")
	whRead := c.requireOrgPerm("webhooks:read")
	whCreate := c.requireOrgPerm("webhooks:create")
	whDelete := c.requireOrgPerm("webhooks:delete")
	orgRead := c.requireOrgPerm("org:read")

	mux.Handle("GET /v1/orgs/{slug}/me", orgRead(http.HandlerFunc(c.handleOrgMe)))

	// Controls library (read-only, library is global).
	mux.Handle("GET /v1/orgs/{slug}/frameworks", read(http.HandlerFunc(c.handleFrameworks)))
	mux.Handle("GET /v1/orgs/{slug}/controls", read(http.HandlerFunc(c.handleControls)))
	mux.Handle("GET /v1/orgs/{slug}/controls/{id}", read(http.HandlerFunc(c.handleControl)))

	// Run lifecycle.
	mux.Handle("POST /v1/orgs/{slug}/check", runCreate(http.HandlerFunc(c.handleCheck)))
	mux.Handle("GET /v1/orgs/{slug}/findings", runRead(http.HandlerFunc(c.handleFindings)))
	mux.Handle("GET /v1/orgs/{slug}/runs", runRead(http.HandlerFunc(c.handleListRuns)))
	mux.Handle("GET /v1/orgs/{slug}/runs/{id}", runRead(http.HandlerFunc(c.handleGetRun)))
	mux.Handle("GET /v1/orgs/{slug}/events", runRead(http.HandlerFunc(c.handleEvents)))

	// Per-org control overrides — the SaaS replacement for concord.yaml.
	mux.Handle("GET /v1/orgs/{slug}/overrides", read(http.HandlerFunc(c.handleListOverrides)))
	mux.Handle("GET /v1/orgs/{slug}/controls/{id}/overrides", read(http.HandlerFunc(c.handleGetOverride)))
	mux.Handle("PUT /v1/orgs/{slug}/controls/{id}/overrides", override(http.HandlerFunc(c.handlePutOverride)))
	mux.Handle("DELETE /v1/orgs/{slug}/controls/{id}/overrides", override(http.HandlerFunc(c.handleDeleteOverride)))

	// Scheduled runs.
	mux.Handle("GET /v1/orgs/{slug}/schedule", runRead(http.HandlerFunc(c.handleGetSchedule)))
	mux.Handle("PUT /v1/orgs/{slug}/schedule", runCreate(http.HandlerFunc(c.handlePutSchedule)))
	mux.Handle("DELETE /v1/orgs/{slug}/schedule", runCreate(http.HandlerFunc(c.handleDeleteSchedule)))

	// Outbound webhooks.
	mux.Handle("GET /v1/orgs/{slug}/webhooks", whRead(http.HandlerFunc(c.handleListWebhooks)))
	mux.Handle("POST /v1/orgs/{slug}/webhooks", whCreate(http.HandlerFunc(c.handleCreateWebhook)))
	mux.Handle("GET /v1/orgs/{slug}/webhooks/{id}", whRead(http.HandlerFunc(c.handleGetWebhook)))
	mux.Handle("PUT /v1/orgs/{slug}/webhooks/{id}", whCreate(http.HandlerFunc(c.handleUpdateWebhook)))
	mux.Handle("DELETE /v1/orgs/{slug}/webhooks/{id}", whDelete(http.HandlerFunc(c.handleDeleteWebhook)))
}
