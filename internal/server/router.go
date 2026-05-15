package server

import (
	"net/http"

	"github.com/concord-dev/concord/internal/server/handlers/admin"
	"github.com/concord-dev/concord/internal/server/handlers/auth"
	"github.com/concord-dev/concord/internal/server/handlers/org"
	"github.com/concord-dev/concord/internal/server/handlers/public"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/server/middleware"
)

// Router returns the fully wired HTTP handler. The mount order is:
//
//  1. Public routes (no auth).
//  2. Auth lifecycle (POST /v1/auth/{login,logout}).
//  3. Admin (CONCORD_ADMIN_TOKEN required).
//  4. Session-only endpoints (current user, list orgs).
//  5. Org-scoped API (Bearer API token OR Bearer session token), each route
//     gated by a specific RBAC permission via RequireOrgPerm.
//
// The whole tree is wrapped in the logging middleware before being returned.
func (c *Concord) Router() http.Handler {
	mw := middleware.New(c.Store, c.AdminToken)
	pub := public.New(c.Version, c.Controls)
	au := auth.New(c.Store, c.SessionTTL)
	ad := admin.New(c.Store)
	og := org.New(c.Store, c.Controls, c.worker, c.bus)

	mux := http.NewServeMux()
	mountPublic(mux, pub)
	mountAuth(mux, au, mw)
	mountAdmin(mux, ad, mw)
	mountSession(mux, au, mw)
	mountOrgAPI(mux, og, mw)
	return httpx.Logging(mux)
}

func mountPublic(mux *http.ServeMux, h *public.Handlers) {
	mux.HandleFunc("GET /healthz", h.Health)
	mux.HandleFunc("GET /version", h.Version)
	mux.HandleFunc("GET /openapi.yaml", h.OpenAPI)
	mux.HandleFunc("GET /docs", h.Docs)
}

func mountAuth(mux *http.ServeMux, h *auth.Handlers, mw *middleware.Middleware) {
	mux.HandleFunc("POST /v1/auth/login", h.Login)
	mux.Handle("POST /v1/auth/logout", mw.RequireSession(http.HandlerFunc(h.Logout)))
}

func mountAdmin(mux *http.ServeMux, h *admin.Handlers, mw *middleware.Middleware) {
	gate := mw.RequireAdmin

	mux.Handle("POST /admin/v1/orgs", gate(http.HandlerFunc(h.CreateOrg)))
	mux.Handle("GET /admin/v1/orgs", gate(http.HandlerFunc(h.ListOrgs)))
	mux.Handle("GET /admin/v1/orgs/{slug}", gate(http.HandlerFunc(h.GetOrg)))

	mux.Handle("POST /admin/v1/orgs/{slug}/tokens", gate(http.HandlerFunc(h.CreateToken)))
	mux.Handle("GET /admin/v1/orgs/{slug}/tokens", gate(http.HandlerFunc(h.ListTokens)))
	mux.Handle("DELETE /admin/v1/orgs/{slug}/tokens/{tokenID}", gate(http.HandlerFunc(h.RevokeToken)))

	mux.Handle("POST /admin/v1/orgs/{slug}/members", gate(http.HandlerFunc(h.AddMember)))
	mux.Handle("GET /admin/v1/orgs/{slug}/members", gate(http.HandlerFunc(h.ListMembers)))
	mux.Handle("DELETE /admin/v1/orgs/{slug}/members/{userID}", gate(http.HandlerFunc(h.RemoveMember)))

	mux.Handle("POST /admin/v1/users", gate(http.HandlerFunc(h.CreateUser)))
	mux.Handle("GET /admin/v1/users", gate(http.HandlerFunc(h.ListUsers)))
	mux.Handle("GET /admin/v1/roles", gate(http.HandlerFunc(h.ListRoles)))
	mux.Handle("GET /admin/v1/permissions", gate(http.HandlerFunc(h.ListPermissions)))
}

func mountSession(mux *http.ServeMux, h *auth.Handlers, mw *middleware.Middleware) {
	mux.Handle("GET /v1/me", mw.RequireSession(http.HandlerFunc(h.Me)))
	mux.Handle("GET /v1/me/orgs", mw.RequireSession(http.HandlerFunc(h.MyOrgs)))
}

func mountOrgAPI(mux *http.ServeMux, h *org.Handlers, mw *middleware.Middleware) {
	read := mw.RequireOrgPerm("controls:read")
	runRead := mw.RequireOrgPerm("runs:read")
	runCreate := mw.RequireOrgPerm("runs:create")
	override := mw.RequireOrgPerm("controls:override")
	whRead := mw.RequireOrgPerm("webhooks:read")
	whCreate := mw.RequireOrgPerm("webhooks:create")
	whDelete := mw.RequireOrgPerm("webhooks:delete")
	orgRead := mw.RequireOrgPerm("org:read")

	mux.Handle("GET /v1/orgs/{slug}/me", orgRead(http.HandlerFunc(h.Me)))

	// Controls library (read-only, library is global).
	mux.Handle("GET /v1/orgs/{slug}/frameworks", read(http.HandlerFunc(h.Frameworks)))
	mux.Handle("GET /v1/orgs/{slug}/controls", read(http.HandlerFunc(h.Controls)))
	mux.Handle("GET /v1/orgs/{slug}/controls/{id}", read(http.HandlerFunc(h.Control)))

	// Run lifecycle.
	mux.Handle("POST /v1/orgs/{slug}/check", runCreate(http.HandlerFunc(h.Check)))
	mux.Handle("GET /v1/orgs/{slug}/findings", runRead(http.HandlerFunc(h.Findings)))
	mux.Handle("GET /v1/orgs/{slug}/runs", runRead(http.HandlerFunc(h.ListRuns)))
	mux.Handle("GET /v1/orgs/{slug}/runs/{id}", runRead(http.HandlerFunc(h.GetRun)))
	mux.Handle("GET /v1/orgs/{slug}/events", runRead(http.HandlerFunc(h.Events)))

	// Per-org control overrides — the SaaS replacement for concord.yaml.
	mux.Handle("GET /v1/orgs/{slug}/overrides", read(http.HandlerFunc(h.ListOverrides)))
	mux.Handle("GET /v1/orgs/{slug}/controls/{id}/overrides", read(http.HandlerFunc(h.GetOverride)))
	mux.Handle("PUT /v1/orgs/{slug}/controls/{id}/overrides", override(http.HandlerFunc(h.PutOverride)))
	mux.Handle("DELETE /v1/orgs/{slug}/controls/{id}/overrides", override(http.HandlerFunc(h.DeleteOverride)))

	// Scheduled runs.
	mux.Handle("GET /v1/orgs/{slug}/schedule", runRead(http.HandlerFunc(h.GetSchedule)))
	mux.Handle("PUT /v1/orgs/{slug}/schedule", runCreate(http.HandlerFunc(h.PutSchedule)))
	mux.Handle("DELETE /v1/orgs/{slug}/schedule", runCreate(http.HandlerFunc(h.DeleteSchedule)))

	// Outbound webhooks.
	mux.Handle("GET /v1/orgs/{slug}/webhooks", whRead(http.HandlerFunc(h.ListWebhooks)))
	mux.Handle("POST /v1/orgs/{slug}/webhooks", whCreate(http.HandlerFunc(h.CreateWebhook)))
	mux.Handle("GET /v1/orgs/{slug}/webhooks/{id}", whRead(http.HandlerFunc(h.GetWebhook)))
	mux.Handle("PUT /v1/orgs/{slug}/webhooks/{id}", whCreate(http.HandlerFunc(h.UpdateWebhook)))
	mux.Handle("DELETE /v1/orgs/{slug}/webhooks/{id}", whDelete(http.HandlerFunc(h.DeleteWebhook)))
}
