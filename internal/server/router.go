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

// Router returns the fully wired HTTP handler. The mount order is:
//
//  1. Public routes (no auth) — includes the per-org trust portal.
//  2. Auth lifecycle (POST /v1/auth/{login,logout}).
//  3. Operator (CONCORD_OPERATOR_TOKEN required) — the SaaS-operator
//     back-door for provisioning tenants.
//  4. Session-only endpoints (current user, list orgs).
//  5. Org-scoped API (Bearer API token OR Bearer session token), each
//     route gated by a specific RBAC permission via RequireOrgPerm.
//
// The whole tree is wrapped in the logging middleware before being returned.
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

	// Stack order:
	//   RequestID(Logging(Metrics(SecurityHeaders(CORS(mux)))))
	//
	// RequestID is the outermost so the request context it injects is
	// visible to every downstream middleware. Metrics sits inside Logging
	// because it reads r.Pattern (set during ServeMux routing) and we
	// want the access log's duration to bracket the metrics observation.
	// SecurityHeaders sits inside Metrics (still outside CORS) so 4xx/5xx
	// responses minted before reaching the handler still carry the hardening
	// headers, and so SecurityHeaders can skip CORS preflights via the
	// Access-Control-Request-Method sniff without racing with the CORS
	// middleware's short-circuit.
	corsMW := cors.New(cors.Config{AllowedOrigins: c.CORSAllowedOrigins})
	secHdr := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})

	// Wrap the entire stack in otelhttp so every request gets a server
	// span. otelhttp creates the span BEFORE the mux has matched, so we
	// can't compute the canonical span name (`POST /v1/orgs/{slug}/runs`)
	// from r.Pattern at creation time.
	//
	// renameSpanFromPattern fixes this AFTER the mux dispatches. It must
	// sit INSIDE every middleware that does `r.WithContext(...)`
	// (RequestID is the only one in our stack), because each WithContext
	// creates a NEW *http.Request struct and the mux's r.Pattern
	// mutation is only visible to whichever wrapper holds the
	// final-most reference. Placing the renamer immediately around the
	// mux means it shares *http.Request with the mux's dispatch.
	core := middleware.RequestID(
		httpx.Logging(
			c.metrics.Middleware(
				secHdr(corsMW(renameSpanFromPattern(mux))))))
	return otelhttp.NewHandler(core, "concord.http")
}

// renameSpanFromPattern updates the otelhttp server span's name to the
// matched route pattern AFTER the mux dispatches, so traces show
// "POST /v1/orgs/{slug}/runs" instead of the generic "concord.http"
// fallback. Bounded cardinality — same approach as the metrics labels.
//
// We rewrite the name AFTER next.ServeHTTP returns so r.Pattern is set
// (Go's ServeMux fills it during dispatch). The span is still active in
// the response goroutine — otelhttp ends it after our handler returns.
func renameSpanFromPattern(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		// Go's ServeMux patterns are "METHOD /path", so r.Pattern is
		// already the canonical span name we want — don't double-
		// prepend the method.
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
	// Public trust portal — opt-in per org; 404s when disabled.
	mux.HandleFunc("GET /v1/orgs/{slug}/trust-portal", h.TrustPortal)
	// Invitation accept flow — public because the invitee doesn't have a
	// session yet. Token in the URL/body is the proof.
	mux.HandleFunc("GET /v1/invitations/accept", h.PreviewInvitation)
	mux.HandleFunc("POST /v1/invitations/accept", h.AcceptInvitation)
}

func mountAuth(mux *http.ServeMux, h *auth.Handlers, mw *middleware.Middleware) {
	mux.HandleFunc("POST /v1/auth/login", h.Login)
	// Second leg of login when the user has MFA enrolled. Unauthenticated:
	// the MFA-challenge token in the body is the proof.
	mux.HandleFunc("POST /v1/auth/login/mfa", h.LoginMFA)
	mux.Handle("POST /v1/auth/logout", mw.RequireSession(http.HandlerFunc(h.Logout)))
	// Password reset is unauthenticated by design — that's the whole point of
	// "forgot password". Token in the body is the proof.
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

	// Auditor population — cross-org read-only principals (external
	// auditors). Operator-managed; per-org admins cannot self-promote.
	mux.Handle("GET /operator/v1/auditors", gate(http.HandlerFunc(h.ListAuditors)))
	mux.Handle("POST /operator/v1/auditors", gate(http.HandlerFunc(h.GrantAuditor)))
	mux.Handle("DELETE /operator/v1/auditors", gate(http.HandlerFunc(h.RevokeAuditor)))

	// Dead-letter queue inspection + replay — Phase 4. Two surfaces:
	// /dlq/events covers event_outbox rows that exhausted the
	// dispatcher's retry budget; /dlq/deliveries covers webhook_delivery
	// rows the retrier abandoned at status='dead'. Replay clears the
	// retry state so the dispatcher/retrier picks the row up again;
	// abandon is a reversible "operator gave up" marker that hides the
	// row from both background loops without losing forensic columns.
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
	// MFA enrollment / management — session-only. The disable + regenerate
	// endpoints re-check the user's password inside the handler so a
	// stolen session can't strip the second factor on its own.
	mux.Handle("GET /v1/me/mfa", mw.RequireSession(http.HandlerFunc(h.GetMFAStatus)))
	mux.Handle("POST /v1/me/mfa/totp/enroll", mw.RequireSession(http.HandlerFunc(h.EnrollTOTP)))
	mux.Handle("POST /v1/me/mfa/totp/verify", mw.RequireSession(http.HandlerFunc(h.VerifyTOTP)))
	mux.Handle("POST /v1/me/mfa/disable", mw.RequireSession(http.HandlerFunc(h.DisableMFA)))
	mux.Handle("POST /v1/me/mfa/recovery-codes/regenerate",
		mw.RequireSession(http.HandlerFunc(h.RegenerateRecoveryCodes)))
}

func mountOrgAPI(mux *http.ServeMux, h *org.Handlers, mw *middleware.Middleware, idem func(http.Handler) http.Handler) {
	// idem may be nil in tests that construct a Concord without
	// wiring Redis. Make it a pass-through so the routes still work.
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

	// Controls library (read-only, library is global).
	mux.Handle("GET /v1/orgs/{slug}/frameworks", read(http.HandlerFunc(h.Frameworks)))
	mux.Handle("GET /v1/orgs/{slug}/controls", read(http.HandlerFunc(h.Controls)))
	mux.Handle("GET /v1/orgs/{slug}/controls/{id}", read(http.HandlerFunc(h.Control)))

	// Runs — single entry point: agents POST completed runs here.
	// Idempotency-Key gates the POST so a network-retrying agent can
	// re-submit the same run without creating two rows. Mounted INSIDE
	// the perm gate so the dedupe slot is only claimed for callers
	// that pass authorization (otherwise an unauthenticated client
	// could exhaust the Redis keyspace).
	mux.Handle("POST /v1/orgs/{slug}/runs", runCreate(idem(http.HandlerFunc(h.SubmitRun))))
	mux.Handle("GET /v1/orgs/{slug}/findings", runRead(http.HandlerFunc(h.Findings)))
	mux.Handle("GET /v1/orgs/{slug}/runs", runRead(http.HandlerFunc(h.ListRuns)))
	mux.Handle("GET /v1/orgs/{slug}/runs/{id}", runRead(http.HandlerFunc(h.GetRun)))
	mux.Handle("GET /v1/orgs/{slug}/events", runRead(http.HandlerFunc(h.Events)))
	// Drift inbox: per-control regression / remediation history. Gated by
	// runs:read because drift is meta-on-runs — no separate permission.
	mux.Handle("GET /v1/orgs/{slug}/drift", runRead(http.HandlerFunc(h.ListDriftEvents)))

	// Per-org control overrides (read on the server; agents can fetch and
	// apply locally before running).
	mux.Handle("GET /v1/orgs/{slug}/overrides", read(http.HandlerFunc(h.ListOverrides)))
	mux.Handle("GET /v1/orgs/{slug}/controls/{id}/overrides", read(http.HandlerFunc(h.GetOverride)))
	mux.Handle("PUT /v1/orgs/{slug}/controls/{id}/overrides", override(http.HandlerFunc(h.PutOverride)))
	mux.Handle("DELETE /v1/orgs/{slug}/controls/{id}/overrides", override(http.HandlerFunc(h.DeleteOverride)))

	// Invitations: org admins invite teammates by email. The accept flow
	// lives under /v1/invitations/accept (public) — see mountPublic.
	mux.Handle("POST /v1/orgs/{slug}/invitations", memInvite(idem(http.HandlerFunc(h.CreateInvitation))))
	mux.Handle("GET /v1/orgs/{slug}/invitations", memInvite(http.HandlerFunc(h.ListInvitations)))
	mux.Handle("DELETE /v1/orgs/{slug}/invitations/{id}", memInvite(http.HandlerFunc(h.RevokeInvitation)))

	// Audit log read (owner + admin via the audit:read permission).
	mux.Handle("GET /v1/orgs/{slug}/audit", auditRead(http.HandlerFunc(h.ListAuditEvents)))
	// One-shot evidence bundle for compliance reviews. Same audit:read
	// permission so auditors with the cross-org flag can pull bundles
	// on every tenant in scope.
	mux.Handle("GET /v1/orgs/{slug}/audit-package", auditRead(http.HandlerFunc(h.ExportAuditPackage)))

	// Trust portal opt-in toggle. The public render lives in mountPublic.
	mux.Handle("GET /v1/orgs/{slug}/trust-portal/settings", orgRead(http.HandlerFunc(h.GetTrustPortalSettings)))
	mux.Handle("PUT /v1/orgs/{slug}/trust-portal/settings", tpManage(http.HandlerFunc(h.PutTrustPortalSettings)))

	// Outbound webhooks (server fires these when agents submit runs).
	mux.Handle("GET /v1/orgs/{slug}/webhooks", whRead(http.HandlerFunc(h.ListWebhooks)))
	mux.Handle("POST /v1/orgs/{slug}/webhooks", whCreate(idem(http.HandlerFunc(h.CreateWebhook))))
	mux.Handle("GET /v1/orgs/{slug}/webhooks/{id}", whRead(http.HandlerFunc(h.GetWebhook)))
	mux.Handle("PUT /v1/orgs/{slug}/webhooks/{id}", whCreate(http.HandlerFunc(h.UpdateWebhook)))
	mux.Handle("DELETE /v1/orgs/{slug}/webhooks/{id}", whDelete(http.HandlerFunc(h.DeleteWebhook)))
}
