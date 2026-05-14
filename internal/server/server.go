// Package server hosts Concord's HTTP API. It speaks two auth mechanisms:
//
//   - API tokens (Authorization: Bearer concord_...) for CI/CLI
//   - User sessions (Authorization: Bearer concord_sess_... OR Cookie) for
//     the web dashboard
//
// Both paths converge on a principal carrying the resolved org and (for
// session auth) the user. Per-endpoint permission checks consult the RBAC
// tables via Store.HasPermission.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/config"
	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/report"
	"github.com/concord-dev/concord/internal/store"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Concord bundles in-memory state + Store.
type Concord struct {
	Controls   []controls.Loaded
	Config     *config.Config
	Registry   *evidence.Registry
	Store      *store.Store
	AdminToken string
	Version    string
	SessionTTL time.Duration

	worker *Worker
	bus    *Bus
	mu     sync.Mutex
}

// Options is the construction surface for cmd/server.
type Options struct {
	ControlsDir  string
	ConfigPath   string
	FixturesOnly bool
	Registry     *evidence.Registry
	Store        *store.Store
	AdminToken   string
	Version      string
	SessionTTL   time.Duration // default: 24h
	Worker       WorkerOpts
}

// NewConcord loads controls + config and wires the Store.
func NewConcord(opts Options) (*Concord, error) {
	if opts.Store == nil {
		return nil, errors.New("Store is required")
	}
	if opts.ControlsDir == "" {
		opts.ControlsDir = "./controls"
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = "./concord.yaml"
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 24 * time.Hour
	}
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	loaded, err := controls.Load(opts.ControlsDir)
	if err != nil {
		return nil, fmt.Errorf("loading controls: %w", err)
	}
	if len(loaded) == 0 {
		return nil, fmt.Errorf("no controls found in %s", opts.ControlsDir)
	}
	reg := opts.Registry
	if reg == nil {
		reg = evidence.NewRegistry()
		if opts.FixturesOnly {
			reg.SetFixturesOnly(true)
		}
	}
	c := &Concord{
		Controls:   loaded,
		Config:     cfg,
		Registry:   reg,
		Store:      opts.Store,
		AdminToken: opts.AdminToken,
		Version:    opts.Version,
		SessionTTL: opts.SessionTTL,
		bus:        NewBus(),
	}
	c.worker = NewWorker(c, opts.Worker)
	c.worker.Start()
	return c, nil
}

// Shutdown drains the background worker.
func (c *Concord) Shutdown(ctx context.Context) error { return c.worker.Shutdown(ctx) }

// Bus exposes the event bus to callers that subscribe (the SSE handler).
func (c *Concord) Bus() *Bus { return c.bus }

// Router returns the fully wired HTTP handler.
func (c *Concord) Router() http.Handler {
	mux := http.NewServeMux()

	// Public.
	mux.HandleFunc("GET /healthz", c.handleHealth)
	mux.HandleFunc("GET /version", c.handleVersion)

	// Auth (session lifecycle).
	mux.HandleFunc("POST /v1/auth/login", c.handleLogin)
	mux.Handle("POST /v1/auth/logout", c.requireSession(http.HandlerFunc(c.handleLogout)))

	// Admin (CONCORD_ADMIN_TOKEN).
	mux.Handle("POST /admin/v1/orgs", c.requireAdmin(http.HandlerFunc(c.handleAdminCreateOrg)))
	mux.Handle("GET /admin/v1/orgs", c.requireAdmin(http.HandlerFunc(c.handleAdminListOrgs)))
	mux.Handle("GET /admin/v1/orgs/{slug}", c.requireAdmin(http.HandlerFunc(c.handleAdminGetOrg)))
	mux.Handle("POST /admin/v1/orgs/{slug}/tokens", c.requireAdmin(http.HandlerFunc(c.handleAdminCreateToken)))
	mux.Handle("GET /admin/v1/orgs/{slug}/tokens", c.requireAdmin(http.HandlerFunc(c.handleAdminListTokens)))
	mux.Handle("DELETE /admin/v1/orgs/{slug}/tokens/{tokenID}", c.requireAdmin(http.HandlerFunc(c.handleAdminRevokeToken)))
	mux.Handle("POST /admin/v1/orgs/{slug}/members", c.requireAdmin(http.HandlerFunc(c.handleAdminAddMember)))
	mux.Handle("GET /admin/v1/orgs/{slug}/members", c.requireAdmin(http.HandlerFunc(c.handleAdminListMembers)))
	mux.Handle("DELETE /admin/v1/orgs/{slug}/members/{userID}", c.requireAdmin(http.HandlerFunc(c.handleAdminRemoveMember)))
	mux.Handle("POST /admin/v1/users", c.requireAdmin(http.HandlerFunc(c.handleAdminCreateUser)))
	mux.Handle("GET /admin/v1/users", c.requireAdmin(http.HandlerFunc(c.handleAdminListUsers)))
	mux.Handle("GET /admin/v1/roles", c.requireAdmin(http.HandlerFunc(c.handleAdminListRoles)))
	mux.Handle("GET /admin/v1/permissions", c.requireAdmin(http.HandlerFunc(c.handleAdminListPermissions)))

	// User-session API: an authenticated human, scoped to one org via path.
	mux.Handle("GET /v1/me", c.requireSession(http.HandlerFunc(c.handleSessionMe)))
	mux.Handle("GET /v1/me/orgs", c.requireSession(http.HandlerFunc(c.handleSessionOrgs)))

	// Org API. Each request resolves to an org via either an API token
	// (Bearer concord_...) or a session token (Bearer concord_sess_...) plus
	// the org slug in the URL.
	mux.Handle("GET /v1/orgs/{slug}/me",
		c.requireOrgPerm("org:read")(http.HandlerFunc(c.handleOrgMe)))
	mux.Handle("GET /v1/orgs/{slug}/frameworks",
		c.requireOrgPerm("controls:read")(http.HandlerFunc(c.handleFrameworks)))
	mux.Handle("GET /v1/orgs/{slug}/controls",
		c.requireOrgPerm("controls:read")(http.HandlerFunc(c.handleControls)))
	mux.Handle("GET /v1/orgs/{slug}/controls/{id}",
		c.requireOrgPerm("controls:read")(http.HandlerFunc(c.handleControl)))
	mux.Handle("POST /v1/orgs/{slug}/check",
		c.requireOrgPerm("runs:create")(http.HandlerFunc(c.handleCheck)))
	mux.Handle("GET /v1/orgs/{slug}/findings",
		c.requireOrgPerm("runs:read")(http.HandlerFunc(c.handleFindings)))
	mux.Handle("GET /v1/orgs/{slug}/runs",
		c.requireOrgPerm("runs:read")(http.HandlerFunc(c.handleListRuns)))
	mux.Handle("GET /v1/orgs/{slug}/runs/{id}",
		c.requireOrgPerm("runs:read")(http.HandlerFunc(c.handleGetRun)))
	mux.Handle("GET /v1/orgs/{slug}/events",
		c.requireOrgPerm("runs:read")(http.HandlerFunc(c.handleEvents)))

	return logging(mux)
}

// ─── Auth primitives ───────────────────────────────────────────────────

// principal is everything we need to know about who's calling. Exactly one
// of TokenID or UserID is non-nil; Org is non-zero for org-scoped requests.
type principal struct {
	Org     store.Organization
	TokenID *uuid.UUID
	UserID  *uuid.UUID
}

type principalCtxKey struct{}

// principalFromContext returns the auth context, if any.
func principalFromContext(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(principal)
	return p, ok
}

type sessionCtxKey struct{}

// sessionUserFromContext returns the user injected by requireSession.
func sessionUserFromContext(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(sessionCtxKey{}).(store.User)
	return u, ok
}

// requireAdmin gates /admin/v1/* on a constant-time match against the
// CONCORD_ADMIN_TOKEN. When the env var is unset the route returns 503.
func (c *Concord) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.AdminToken == "" {
			writeError(w, http.StatusServiceUnavailable,
				"admin endpoints disabled (set CONCORD_ADMIN_TOKEN)")
			return
		}
		tok, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(c.AdminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireSession resolves a session token and injects the user into context.
// Session tokens are distinguished from API tokens by their prefix.
func (c *Concord) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		if !strings.HasPrefix(tok, "concord_sess_") {
			writeError(w, http.StatusUnauthorized, "expected a session token")
			return
		}
		sess, err := c.Store.ResolveSession(r.Context(), tok)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid or expired session")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		u, err := c.Store.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey{}, u)
		// Attach the session id too so logout can revoke it.
		ctx = context.WithValue(ctx, sessionIDCtxKey{}, sess.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type sessionIDCtxKey struct{}

// requireOrgPerm requires either an API token or a session token authenticating
// for the org named by the {slug} path variable, AND that the caller hold the
// named permission. API tokens implicitly carry every permission of their org;
// users must have a role that grants `perm` via role_permission.
func (c *Concord) requireOrgPerm(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slug := r.PathValue("slug")
			org, err := c.Store.GetOrganizationBySlug(r.Context(), slug)
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "no organization with slug "+slug)
				return
			}
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}

			tok, ok := bearerToken(r)
			if !ok {
				writeError(w, http.StatusUnauthorized, "missing Authorization header")
				return
			}

			var p principal
			p.Org = org

			switch {
			case strings.HasPrefix(tok, "concord_sess_"):
				sess, err := c.Store.ResolveSession(r.Context(), tok)
				if errors.Is(err, store.ErrNotFound) {
					writeError(w, http.StatusUnauthorized, "invalid or expired session")
					return
				}
				if err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
				has, err := c.Store.HasPermission(r.Context(), sess.UserID, org.ID, perm)
				if err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
				if !has {
					writeError(w, http.StatusForbidden,
						fmt.Sprintf("missing permission %q on org %q", perm, slug))
					return
				}
				p.UserID = &sess.UserID

			default:
				// Treat as API token.
				at, err := c.Store.ResolveAPIToken(r.Context(), tok)
				if errors.Is(err, store.ErrNotFound) {
					writeError(w, http.StatusUnauthorized, "invalid token")
					return
				}
				if err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
				if at.OrgID != org.ID {
					writeError(w, http.StatusForbidden, "token is not scoped to this org")
					return
				}
				p.TokenID = &at.ID
			}

			ctx := context.WithValue(r.Context(), principalCtxKey{}, p)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken extracts the token from Authorization: Bearer <x>.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	return tok, tok != ""
}

// ─── Public ────────────────────────────────────────────────────────────

func (c *Concord) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (c *Concord) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  c.Version,
		"controls": len(c.Controls),
	})
}

// ─── Login + session ──────────────────────────────────────────────────

func (c *Concord) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	user, err := c.Store.VerifyUserPassword(r.Context(), body.Email, body.Password)
	if errors.Is(err, store.ErrNotFound) {
		// Same error for unknown user and bad password — prevents user enumeration.
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess, plain, err := c.Store.CreateSession(r.Context(), user.ID, c.SessionTTL,
		clientIP(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id": sess.ID,
		"token":      plain,
		"expires_at": sess.ExpiresAt,
		"user":       user,
		"note":       "Pass this token in `Authorization: Bearer <token>` on subsequent requests.",
	})
}

func (c *Concord) handleLogout(w http.ResponseWriter, r *http.Request) {
	sid, ok := r.Context().Value(sessionIDCtxKey{}).(uuid.UUID)
	if !ok {
		writeError(w, http.StatusInternalServerError, "session id missing from context")
		return
	}
	if err := c.Store.RevokeSession(r.Context(), sid); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// clientIP picks the leftmost X-Forwarded-For entry when behind a proxy,
// falling back to RemoteAddr's host portion.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// ─── Session-scoped endpoints (no org context) ─────────────────────────

func (c *Concord) handleSessionMe(w http.ResponseWriter, r *http.Request) {
	u, _ := sessionUserFromContext(r.Context())
	writeJSON(w, http.StatusOK, u)
}

func (c *Concord) handleSessionOrgs(w http.ResponseWriter, r *http.Request) {
	u, _ := sessionUserFromContext(r.Context())
	orgs, err := c.Store.ListUserOrgs(r.Context(), u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, orgs)
}

// ─── Admin: orgs ───────────────────────────────────────────────────────

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

// ─── Admin: users ──────────────────────────────────────────────────────

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

// ─── Admin: roles + permissions ────────────────────────────────────────

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

// ─── Admin: memberships ───────────────────────────────────────────────

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
	// Resolve every role name up front so an invalid role rejects the whole
	// request before any insert.
	roleIDs := make([]uuid.UUID, 0, len(body.Roles))
	for _, name := range body.Roles {
		r0, err := c.Store.GetRoleByName(r.Context(), name)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "unknown role "+name)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		roleIDs = append(roleIDs, r0.ID)
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

// ─── Admin: tokens ────────────────────────────────────────────────────

func (c *Concord) handleAdminCreateToken(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	var body struct {
		Name             string `json:"name"`
		CreatedByEmail   string `json:"created_by_email,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	var createdBy *uuid.UUID
	if body.CreatedByEmail != "" {
		u, err := c.Store.GetUserByEmail(r.Context(), body.CreatedByEmail)
		if err != nil {
			writeError(w, http.StatusBadRequest, "created_by_email not found")
			return
		}
		createdBy = &u.ID
	}
	tok, plain, err := c.Store.CreateAPIToken(r.Context(), org.ID, body.Name, createdBy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":                  tok.ID,
		"org_id":              tok.OrgID,
		"name":                tok.Name,
		"created_by_user_id":  tok.CreatedByUserID,
		"created_at":          tok.CreatedAt,
		"token":               plain,
		"note":                "Save this token now — it cannot be retrieved later.",
	})
}

func (c *Concord) handleAdminListTokens(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	toks, err := c.Store.ListAPITokens(r.Context(), org.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toks)
}

func (c *Concord) handleAdminRevokeToken(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	tokenID, err := uuid.Parse(r.PathValue("tokenID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	if err := c.Store.RevokeAPIToken(r.Context(), org.ID, tokenID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Org API ──────────────────────────────────────────────────────────

func (c *Concord) handleOrgMe(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	resp := map[string]any{
		"organization": p.Org,
		"token_id":     p.TokenID,
		"user_id":      p.UserID,
	}
	if p.UserID != nil {
		perms, err := c.Store.UserPermissions(r.Context(), *p.UserID, p.Org.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp["permissions"] = perms
	}
	writeJSON(w, http.StatusOK, resp)
}

func (c *Concord) handleFrameworks(w http.ResponseWriter, _ *http.Request) {
	type entry struct {
		Framework string `json:"framework"`
		Controls  int    `json:"controls"`
	}
	counts := make(map[string]int)
	for _, l := range c.Controls {
		counts[l.Control.Metadata.Framework]++
	}
	out := make([]entry, 0, len(counts))
	for fw, n := range counts {
		out = append(out, entry{Framework: fw, Controls: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Framework < out[j].Framework })
	writeJSON(w, http.StatusOK, out)
}

func (c *Concord) handleControls(w http.ResponseWriter, r *http.Request) {
	framework := r.URL.Query().Get("framework")
	out := make([]apiv1.Control, 0, len(c.Controls))
	for _, l := range c.Controls {
		if framework != "" && l.Control.Metadata.Framework != framework {
			continue
		}
		out = append(out, l.Control)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Metadata.Framework != out[j].Metadata.Framework {
			return out[i].Metadata.Framework < out[j].Metadata.Framework
		}
		return out[i].Metadata.ID < out[j].Metadata.ID
	})
	writeJSON(w, http.StatusOK, out)
}

func (c *Concord) handleControl(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target := strings.ToLower(id)
	for _, l := range c.Controls {
		if strings.ToLower(l.Control.Metadata.ID) == target {
			writeJSON(w, http.StatusOK, l.Control)
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Sprintf("no control with id %q", id))
}

func (c *Concord) handleCheck(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "principal missing")
		return
	}
	run, err := c.Store.CreateRun(r.Context(), store.CreateRunParams{
		OrgID: p.Org.ID, TokenID: p.TokenID, UserID: p.UserID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "creating run: "+err.Error())
		return
	}
	if err := c.worker.Enqueue(runJob{OrgID: p.Org.ID, RunID: run.ID}); err != nil {
		_ = c.Store.FailRun(context.Background(), run.ID, err.Error())
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	slug := r.PathValue("slug")
	pollURL := fmt.Sprintf("/v1/orgs/%s/runs/%s", slug, run.ID)
	w.Header().Set("Location", pollURL)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"run_id":     run.ID,
		"status":     string(store.RunPending),
		"poll_url":   pollURL,
		"started_at": run.StartedAt,
	})
}

func (c *Concord) handleFindings(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	runs, err := c.Store.ListRuns(r.Context(), p.Org.ID, 20)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, r0 := range runs {
		if r0.Status != store.RunSucceeded {
			continue
		}
		full, err := c.Store.GetRun(r.Context(), p.Org.ID, r0.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeFindingsEnvelope(w, full)
		return
	}
	writeError(w, http.StatusNotFound, "no succeeded run yet — POST /v1/orgs/{slug}/check first")
}

func (c *Concord) handleListRuns(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	runs, err := c.Store.ListRuns(r.Context(), p.Org.ID, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type listEntry struct {
		ID           uuid.UUID  `json:"id"`
		Status       string     `json:"status"`
		StartedAt    time.Time  `json:"started_at"`
		CompletedAt  *time.Time `json:"completed_at,omitempty"`
		ErrorMessage string     `json:"error_message,omitempty"`
	}
	out := make([]listEntry, 0, len(runs))
	for _, r0 := range runs {
		out = append(out, listEntry{
			ID: r0.ID, Status: string(r0.Status), StartedAt: r0.StartedAt,
			CompletedAt: r0.CompletedAt, ErrorMessage: r0.ErrorMessage,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (c *Concord) handleGetRun(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	runID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid run id")
		return
	}
	run, err := c.Store.GetRun(r.Context(), p.Org.ID, runID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeFindingsEnvelope(w, run)
}

func writeFindingsEnvelope(w http.ResponseWriter, run store.Run) {
	var summary report.Summary
	var findings []apiv1.Finding
	if len(run.Summary) > 0 {
		_ = json.Unmarshal(run.Summary, &summary)
	}
	if len(run.Findings) > 0 {
		_ = json.Unmarshal(run.Findings, &findings)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"run_id":        run.ID,
		"status":        run.Status,
		"started_at":    run.StartedAt,
		"completed_at":  run.CompletedAt,
		"error_message": run.ErrorMessage,
		"summary":       summary,
		"findings":      findings,
	})
}

func (c *Concord) handleEvents(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "principal missing")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ch, unsub := c.bus.Subscribe(p.Org.ID, 32)
	defer unsub()

	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			payload, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Kind, payload)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

// ─── Lookup helpers ────────────────────────────────────────────────────

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

// ─── Tiny HTTP helpers ─────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		_, _ = io.WriteString(w, fmt.Sprintf(`{"error":%q}`, err.Error()))
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		fmt.Fprintf(os.Stderr, "%s %s %d %s\n",
			r.Method, r.URL.Path, rw.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
