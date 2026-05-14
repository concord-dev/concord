// Package server hosts Concord's HTTP API. It is multi-tenant from the
// ground up: every /v1/* request is scoped to an organization resolved from
// an API token, every /admin/v1/* request requires the operator-level
// admin token (the system bootstrap secret).
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

// Concord bundles the in-memory state every handler operates on plus the
// persistent Store. Controls + Config + Registry are global (shared across
// orgs in v1); orgs, users, memberships, tokens, and runs live in the Store.
type Concord struct {
	Controls   []controls.Loaded
	Config     *config.Config
	Registry   *evidence.Registry
	Store      *store.Store
	AdminToken string
	Version    string

	worker *Worker
	bus    *Bus

	mu sync.Mutex // reserved for future per-instance coordination
}

// Options is what the cmd-side wiring passes in to construct a server.
type Options struct {
	ControlsDir  string
	ConfigPath   string
	FixturesOnly bool
	Registry     *evidence.Registry
	Store        *store.Store
	AdminToken   string
	Version      string
	Worker       WorkerOpts
}

// NewConcord loads controls + config and wires the supplied Store. Returns an
// error when the controls dir is empty or the Store is missing.
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
		bus:        NewBus(),
	}
	c.worker = NewWorker(c, opts.Worker)
	c.worker.Start()
	return c, nil
}

// Shutdown drains the background worker.
func (c *Concord) Shutdown(ctx context.Context) error { return c.worker.Shutdown(ctx) }

// Bus returns the event bus for callers that need to publish or subscribe.
func (c *Concord) Bus() *Bus { return c.bus }

// Router wires every endpoint plus the auth middleware. Returned handler is
// ready to mount under net/http.
func (c *Concord) Router() http.Handler {
	mux := http.NewServeMux()

	// Public.
	mux.HandleFunc("GET /healthz", c.handleHealth)
	mux.HandleFunc("GET /version", c.handleVersion)

	// Admin (CONCORD_ADMIN_TOKEN required).
	mux.Handle("POST /admin/v1/orgs", c.requireAdmin(http.HandlerFunc(c.handleAdminCreateOrg)))
	mux.Handle("GET /admin/v1/orgs", c.requireAdmin(http.HandlerFunc(c.handleAdminListOrgs)))
	mux.Handle("GET /admin/v1/orgs/{slug}", c.requireAdmin(http.HandlerFunc(c.handleAdminGetOrg)))
	mux.Handle("POST /admin/v1/orgs/{slug}/tokens", c.requireAdmin(http.HandlerFunc(c.handleAdminCreateToken)))
	mux.Handle("GET /admin/v1/orgs/{slug}/tokens", c.requireAdmin(http.HandlerFunc(c.handleAdminListTokens)))
	mux.Handle("DELETE /admin/v1/orgs/{slug}/tokens/{tokenID}", c.requireAdmin(http.HandlerFunc(c.handleAdminDeleteToken)))
	mux.Handle("POST /admin/v1/orgs/{slug}/members", c.requireAdmin(http.HandlerFunc(c.handleAdminAddMember)))
	mux.Handle("GET /admin/v1/orgs/{slug}/members", c.requireAdmin(http.HandlerFunc(c.handleAdminListMembers)))
	mux.Handle("DELETE /admin/v1/orgs/{slug}/members/{userID}", c.requireAdmin(http.HandlerFunc(c.handleAdminRemoveMember)))
	mux.Handle("POST /admin/v1/users", c.requireAdmin(http.HandlerFunc(c.handleAdminCreateUser)))
	mux.Handle("GET /admin/v1/users", c.requireAdmin(http.HandlerFunc(c.handleAdminListUsers)))

	// Org-scoped API (Authorization: Bearer <api-token>).
	mux.Handle("GET /v1/me", c.requireOrg(http.HandlerFunc(c.handleMe)))
	mux.Handle("GET /v1/frameworks", c.requireOrg(http.HandlerFunc(c.handleFrameworks)))
	mux.Handle("GET /v1/controls", c.requireOrg(http.HandlerFunc(c.handleControls)))
	mux.Handle("GET /v1/controls/{id}", c.requireOrg(http.HandlerFunc(c.handleControl)))
	mux.Handle("POST /v1/check", c.requireOrg(http.HandlerFunc(c.handleCheck)))
	mux.Handle("GET /v1/findings", c.requireOrg(http.HandlerFunc(c.handleFindings)))
	mux.Handle("GET /v1/runs", c.requireOrg(http.HandlerFunc(c.handleListRuns)))
	mux.Handle("GET /v1/runs/{id}", c.requireOrg(http.HandlerFunc(c.handleGetRun)))
	mux.Handle("GET /v1/events", c.requireOrg(http.HandlerFunc(c.handleEvents)))

	return logging(mux)
}

// --- Middleware ---

// principal captures who (or what) is making an authenticated request. For
// API tokens it carries the resolved org + token id; for future user
// sessions, fields will be added without breaking existing handlers.
type principal struct {
	Org     store.Organization
	TokenID *uuid.UUID
}

type principalCtxKey struct{}

// PrincipalFromContext returns the auth context injected by requireOrg.
// The second return is false when called outside an authenticated handler.
func PrincipalFromContext(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(principal)
	return p, ok
}

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

func (c *Concord) requireOrg(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plaintext, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		tok, err := c.Store.ResolveToken(r.Context(), plaintext)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "auth check failed: "+err.Error())
			return
		}
		org, err := c.Store.GetOrganizationByID(r.Context(), tok.OrgID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "org lookup failed")
			return
		}
		p := principal{Org: org, TokenID: &tok.ID}
		ctx := context.WithValue(r.Context(), principalCtxKey{}, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bearerToken extracts the token from an `Authorization: Bearer <x>` header.
// Comparison is case-insensitive to match RFC 6750.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	return tok, tok != ""
}

// --- Public handlers ---

func (c *Concord) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (c *Concord) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  c.Version,
		"controls": len(c.Controls),
	})
}

// --- Admin: orgs ---

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
		writeError(w, http.StatusBadRequest, "both `name` and `slug` are required")
		return
	}
	org, err := c.Store.CreateOrganization(r.Context(), body.Name, body.Slug)
	if err != nil {
		writeError(w, http.StatusConflict, "creating organization: "+err.Error())
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

// --- Admin: users ---

func (c *Concord) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Email == "" || body.Name == "" {
		writeError(w, http.StatusBadRequest, "both `email` and `name` are required")
		return
	}
	u, err := c.Store.CreateUser(r.Context(), body.Email, body.Name)
	if err != nil {
		writeError(w, http.StatusConflict, "creating user: "+err.Error())
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

// --- Admin: memberships ---

func (c *Concord) handleAdminAddMember(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	var body struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	role := store.Role(body.Role)
	if !role.IsValid() {
		writeError(w, http.StatusBadRequest,
			"role must be one of owner|admin|member|viewer")
		return
	}
	// Caller may pass user_id OR email; email path is the convenient one for
	// CLI bootstrapping.
	user, ok := c.lookupUser(w, r, body.UserID, body.Email)
	if !ok {
		return
	}
	m, err := c.Store.AddMember(r.Context(), user.ID, org.ID, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, m)
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
	if err := c.Store.RemoveMember(r.Context(), userID, org.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "membership not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Admin: tokens ---

func (c *Concord) handleAdminCreateToken(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	var body struct {
		Name      string  `json:"name"`
		CreatedBy *string `json:"created_by_email,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "`name` is required")
		return
	}
	var createdBy *uuid.UUID
	if body.CreatedBy != nil && *body.CreatedBy != "" {
		u, err := c.Store.GetUserByEmail(r.Context(), *body.CreatedBy)
		if err != nil {
			writeError(w, http.StatusBadRequest,
				"created_by_email not found among users")
			return
		}
		createdBy = &u.ID
	}
	tok, plain, err := c.Store.CreateToken(r.Context(), org.ID, body.Name, createdBy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         tok.ID,
		"org_id":     tok.OrgID,
		"name":       tok.Name,
		"created_at": tok.CreatedAt,
		"created_by": tok.CreatedBy,
		"token":      plain,
		"note":       "Save this token now — it cannot be retrieved later.",
	})
}

func (c *Concord) handleAdminListTokens(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	toks, err := c.Store.ListTokens(r.Context(), org.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toks)
}

func (c *Concord) handleAdminDeleteToken(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	tokenID, err := uuid.Parse(r.PathValue("tokenID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	if err := c.Store.DeleteToken(r.Context(), org.ID, tokenID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Org API (controls library is global in v1) ---

func (c *Concord) handleMe(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"organization": p.Org,
		"token_id":     p.TokenID,
	})
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

// handleCheck creates a run, enqueues it on the background worker, and
// responds 202 Accepted with the run id. Clients poll GET /v1/runs/{id}.
func (c *Concord) handleCheck(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "principal missing from context")
		return
	}
	run, err := c.Store.CreateRun(r.Context(), p.Org.ID, p.TokenID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "creating run: "+err.Error())
		return
	}
	if err := c.worker.Enqueue(runJob{OrgID: p.Org.ID, RunID: run.ID}); err != nil {
		_ = c.Store.FailRun(context.Background(), run.ID, err.Error())
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	w.Header().Set("Location", "/v1/runs/"+run.ID.String())
	writeJSON(w, http.StatusAccepted, map[string]any{
		"run_id":     run.ID,
		"status":     string(store.RunPending),
		"poll_url":   "/v1/runs/" + run.ID.String(),
		"started_at": run.StartedAt,
	})
}

func (c *Concord) handleFindings(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFromContext(r.Context())
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
	writeError(w, http.StatusNotFound, "no succeeded run yet — POST /v1/check first")
}

func (c *Concord) handleListRuns(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFromContext(r.Context())
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
	p, _ := PrincipalFromContext(r.Context())
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

// handleEvents streams Server-Sent Events for the authenticated org.
// One subscriber per HTTP connection.
func (c *Concord) handleEvents(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "principal missing from context")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported by the underlying ResponseWriter")
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

// --- Lookup helpers ---

// lookupOrgBySlug fetches the org and writes the standard 404 / 500 if
// missing. Returns ok=false when the handler should not continue.
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

// --- Tiny HTTP helpers ---

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

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the wrapped ResponseWriter so the SSE handler's
// w.(http.Flusher) type assertion still passes after logging() wraps the
// response.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
