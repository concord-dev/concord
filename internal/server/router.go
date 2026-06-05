package server

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/concord-dev/concord/internal/server/cors"
	"github.com/concord-dev/concord/internal/server/handlers/auth"
	"github.com/concord-dev/concord/internal/server/handlers/operator"
	"github.com/concord-dev/concord/internal/server/handlers/org"
	"github.com/concord-dev/concord/internal/server/handlers/public"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/server/middleware"
)

func (c *Concord) Router() http.Handler {
	mw := middleware.New(c.Store, c.OperatorToken)
	pub := public.New(c.Version, c.Controls, c.Store, c.pubLimits)
	au := auth.New(c.Store, c.SessionTTL, c.authLimits, c.mailer, c.bg)
	op := operator.New(c.Store)
	og := org.New(c.Store, c.Controls, c.bus, org.Broadcaster{
		RunCompleted:  c.Broadcast,
		DriftDetected: c.BroadcastDrift,
	}, c.mailer, c.bg)

	mux := http.NewServeMux()
	mountPublic(mux, pub)
	mux.Handle("GET /metrics", c.metrics.Handler())
	mountAuth(mux, au, mw)
	mountOperator(mux, op, mw)
	mountSession(mux, au, mw)
	mountOrgAPI(mux, og, mw, c.idempotency)

	corsMW := cors.New(cors.Config{AllowedOrigins: c.CORSAllowedOrigins})
	secHdr := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})

	core := middleware.RequestID(
		httpx.Logging(
			c.metrics.Middleware(
				secHdr(corsMW(renameSpanFromPattern(mux))))))
	return otelhttp.NewHandler(core, "concord.http")
}

func renameSpanFromPattern(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if r.Pattern != "" {
			if span := trace.SpanFromContext(r.Context()); span.IsRecording() {
				span.SetName(r.Pattern)
			}
		}
	})
}

func mountPublic(mux *http.ServeMux, h *public.Handlers) {
	mux.HandleFunc("GET /healthz", h.Health)
	mux.HandleFunc("GET /readyz", h.Ready)
	mux.HandleFunc("GET /version", h.Version)
	mux.HandleFunc("GET /openapi.yaml", h.OpenAPI)
	mux.HandleFunc("GET /docs", h.Docs)
	mux.HandleFunc("GET /v1/orgs/{slug}/trust-portal", h.TrustPortal)
	mux.HandleFunc("GET /v1/invitations/accept", h.PreviewInvitation)
	mux.HandleFunc("POST /v1/invitations/accept", h.AcceptInvitation)
}

func mountAuth(mux *http.ServeMux, h *auth.Handlers, mw *middleware.Middleware) {
	mux.HandleFunc("POST /v1/auth/login", h.Login)
	mux.HandleFunc("POST /v1/auth/login/mfa", h.LoginMFA)
	mux.Handle("POST /v1/auth/logout", mw.RequireSession(http.HandlerFunc(h.Logout)))
	mux.HandleFunc("POST /v1/auth/password-reset", h.RequestPasswordReset)
	mux.HandleFunc("POST /v1/auth/password-reset/confirm", h.ConfirmPasswordReset)
}

func mountOperator(mux *http.ServeMux, h *operator.Handlers, mw *middleware.Middleware) {
	gate := mw.RequireOperator

	mux.Handle("POST /operator/v1/orgs", gate(http.HandlerFunc(h.CreateOrg)))
	mux.Handle("GET /operator/v1/orgs", gate(http.HandlerFunc(h.ListOrgs)))
	mux.Handle("GET /operator/v1/orgs/{slug}", gate(http.HandlerFunc(h.GetOrg)))

	mux.Handle("POST /operator/v1/orgs/{slug}/tokens", gate(http.HandlerFunc(h.CreateToken)))
	mux.Handle("GET /operator/v1/orgs/{slug}/tokens", gate(http.HandlerFunc(h.ListTokens)))
	mux.Handle("DELETE /operator/v1/orgs/{slug}/tokens/{tokenID}", gate(http.HandlerFunc(h.RevokeToken)))

	mux.Handle("POST /operator/v1/orgs/{slug}/members", gate(http.HandlerFunc(h.AddMember)))
	mux.Handle("GET /operator/v1/orgs/{slug}/members", gate(http.HandlerFunc(h.ListMembers)))
	mux.Handle("DELETE /operator/v1/orgs/{slug}/members/{userID}", gate(http.HandlerFunc(h.RemoveMember)))

	mux.Handle("POST /operator/v1/users", gate(http.HandlerFunc(h.CreateUser)))
	mux.Handle("GET /operator/v1/users", gate(http.HandlerFunc(h.ListUsers)))
	mux.Handle("GET /operator/v1/roles", gate(http.HandlerFunc(h.ListRoles)))
	mux.Handle("GET /operator/v1/permissions", gate(http.HandlerFunc(h.ListPermissions)))

	mux.Handle("GET /operator/v1/auditors", gate(http.HandlerFunc(h.ListAuditors)))
	mux.Handle("POST /operator/v1/auditors", gate(http.HandlerFunc(h.GrantAuditor)))
	mux.Handle("DELETE /operator/v1/auditors", gate(http.HandlerFunc(h.RevokeAuditor)))

	mux.Handle("GET /operator/v1/dlq/events", gate(http.HandlerFunc(h.ListDLQEvents)))
	mux.Handle("GET /operator/v1/dlq/events/{id}", gate(http.HandlerFunc(h.GetDLQEvent)))
	mux.Handle("POST /operator/v1/dlq/events/{id}/replay", gate(http.HandlerFunc(h.ReplayDLQEvent)))
	mux.Handle("DELETE /operator/v1/dlq/events/{id}", gate(http.HandlerFunc(h.AbandonDLQEvent)))

	mux.Handle("GET /operator/v1/dlq/deliveries", gate(http.HandlerFunc(h.ListDLQDeliveries)))
	mux.Handle("GET /operator/v1/dlq/deliveries/{id}", gate(http.HandlerFunc(h.GetDLQDelivery)))
	mux.Handle("POST /operator/v1/dlq/deliveries/{id}/replay", gate(http.HandlerFunc(h.ReplayDLQDelivery)))
	mux.Handle("DELETE /operator/v1/dlq/deliveries/{id}", gate(http.HandlerFunc(h.AbandonDLQDelivery)))
}

func mountSession(mux *http.ServeMux, h *auth.Handlers, mw *middleware.Middleware) {
	mux.Handle("GET /v1/me", mw.RequireSession(http.HandlerFunc(h.Me)))
	mux.Handle("GET /v1/me/orgs", mw.RequireSession(http.HandlerFunc(h.MyOrgs)))
	mux.Handle("GET /v1/me/mfa", mw.RequireSession(http.HandlerFunc(h.GetMFAStatus)))
	mux.Handle("POST /v1/me/mfa/totp/enroll", mw.RequireSession(http.HandlerFunc(h.EnrollTOTP)))
	mux.Handle("POST /v1/me/mfa/totp/verify", mw.RequireSession(http.HandlerFunc(h.VerifyTOTP)))
	mux.Handle("POST /v1/me/mfa/disable", mw.RequireSession(http.HandlerFunc(h.DisableMFA)))
	mux.Handle("POST /v1/me/mfa/recovery-codes/regenerate",
		mw.RequireSession(http.HandlerFunc(h.RegenerateRecoveryCodes)))
}

func mountOrgAPI(mux *http.ServeMux, h *org.Handlers, mw *middleware.Middleware, idem func(http.Handler) http.Handler) {
	if idem == nil {
		idem = func(next http.Handler) http.Handler { return next }
	}
	read := mw.RequireOrgPerm("controls:read")
	runRead := mw.RequireOrgPerm("runs:read")
	runCreate := mw.RequireOrgPerm("runs:create")
	override := mw.RequireOrgPerm("controls:override")
	whRead := mw.RequireOrgPerm("webhooks:read")
	whCreate := mw.RequireOrgPerm("webhooks:create")
	whDelete := mw.RequireOrgPerm("webhooks:delete")
	orgRead := mw.RequireOrgPerm("org:read")
	tpManage := mw.RequireOrgPerm("trust_portal:manage")
	memInvite := mw.RequireOrgPerm("members:invite")
	auditRead := mw.RequireOrgPerm("audit:read")

	mux.Handle("GET /v1/orgs/{slug}/me", orgRead(http.HandlerFunc(h.Me)))

	mux.Handle("GET /v1/orgs/{slug}/frameworks", read(http.HandlerFunc(h.Frameworks)))
	mux.Handle("GET /v1/orgs/{slug}/controls", read(http.HandlerFunc(h.Controls)))
	mux.Handle("GET /v1/orgs/{slug}/controls/{id}", read(http.HandlerFunc(h.Control)))

	mux.Handle("POST /v1/orgs/{slug}/runs", runCreate(idem(http.HandlerFunc(h.SubmitRun))))
	mux.Handle("GET /v1/orgs/{slug}/findings", runRead(http.HandlerFunc(h.Findings)))
	mux.Handle("GET /v1/orgs/{slug}/runs", runRead(http.HandlerFunc(h.ListRuns)))
	mux.Handle("GET /v1/orgs/{slug}/runs/{id}", runRead(http.HandlerFunc(h.GetRun)))
	mux.Handle("GET /v1/orgs/{slug}/events", runRead(http.HandlerFunc(h.Events)))
	mux.Handle("GET /v1/orgs/{slug}/drift", runRead(http.HandlerFunc(h.ListDriftEvents)))

	mux.Handle("GET /v1/orgs/{slug}/overrides", read(http.HandlerFunc(h.ListOverrides)))
	mux.Handle("GET /v1/orgs/{slug}/controls/{id}/overrides", read(http.HandlerFunc(h.GetOverride)))
	mux.Handle("PUT /v1/orgs/{slug}/controls/{id}/overrides", override(http.HandlerFunc(h.PutOverride)))
	mux.Handle("DELETE /v1/orgs/{slug}/controls/{id}/overrides", override(http.HandlerFunc(h.DeleteOverride)))

	mux.Handle("POST /v1/orgs/{slug}/invitations", memInvite(idem(http.HandlerFunc(h.CreateInvitation))))
	mux.Handle("GET /v1/orgs/{slug}/invitations", memInvite(http.HandlerFunc(h.ListInvitations)))
	mux.Handle("DELETE /v1/orgs/{slug}/invitations/{id}", memInvite(http.HandlerFunc(h.RevokeInvitation)))

	mux.Handle("GET /v1/orgs/{slug}/audit", auditRead(http.HandlerFunc(h.ListAuditEvents)))
	mux.Handle("GET /v1/orgs/{slug}/audit-package", auditRead(http.HandlerFunc(h.ExportAuditPackage)))

	mux.Handle("GET /v1/orgs/{slug}/trust-portal/settings", orgRead(http.HandlerFunc(h.GetTrustPortalSettings)))
	mux.Handle("PUT /v1/orgs/{slug}/trust-portal/settings", tpManage(http.HandlerFunc(h.PutTrustPortalSettings)))

	mux.Handle("GET /v1/orgs/{slug}/webhooks", whRead(http.HandlerFunc(h.ListWebhooks)))
	mux.Handle("POST /v1/orgs/{slug}/webhooks", whCreate(idem(http.HandlerFunc(h.CreateWebhook))))
	mux.Handle("GET /v1/orgs/{slug}/webhooks/{id}", whRead(http.HandlerFunc(h.GetWebhook)))
	mux.Handle("PUT /v1/orgs/{slug}/webhooks/{id}", whCreate(http.HandlerFunc(h.UpdateWebhook)))
	mux.Handle("DELETE /v1/orgs/{slug}/webhooks/{id}", whDelete(http.HandlerFunc(h.DeleteWebhook)))
}
