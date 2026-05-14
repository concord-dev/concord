// Package server hosts Concord's HTTP API. It is multi-tenant from the
// ground up: every /v1/* request is scoped to a tenant resolved from an API
// token, every /admin/v1/* request requires the operator-level admin token.
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
// tenants in v0); tenants, tokens, and runs live in the Store.
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
	Worker       WorkerOpts // zero value → sensible defaults
}

// NewConcord loads controls + config and wires the supplied Store.
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

// Bus returns the event bus for callers (the watcher's run loop and the SSE
// handler) that need to publish or subscribe.
func (c *Concord) Bus() *Bus { return c.bus }

// Shutdown drains the background worker. Call from the HTTP server's
// shutdown path so in-flight runs finish before the process exits.
func (c *Concord) Shutdown(ctx context.Context) error {
	return c.worker.Shutdown(ctx)
}

// Router wires every endpoint plus the auth middleware. Returned handler is
// ready to mount under net/http.
func (c *Concord) Router() http.Handler {
	mux := http.NewServeMux()

	// Public.
	mux.HandleFunc("GET /healthz", c.handleHealth)
	mux.HandleFunc("GET /version", c.handleVersion)

	// Admin (CONCORD_ADMIN_TOKEN required).
	mux.Handle("POST /admin/v1/tenants", c.requireAdmin(http.HandlerFunc(c.handleAdminCreateTenant)))
	mux.Handle("GET /admin/v1/tenants", c.requireAdmin(http.HandlerFunc(c.handleAdminListTenants)))
	mux.Handle("POST /admin/v1/tenants/{slug}/tokens", c.requireAdmin(http.HandlerFunc(c.handleAdminCreateToken)))
	mux.Handle("GET /admin/v1/tenants/{slug}/tokens", c.requireAdmin(http.HandlerFunc(c.handleAdminListTokens)))
	mux.Handle("DELETE /admin/v1/tenants/{slug}/tokens/{tokenID}", c.requireAdmin(http.HandlerFunc(c.handleAdminDeleteToken)))

	// Tenant API (Authorization: Bearer <api-token>).
	mux.Handle("GET /v1/frameworks", c.requireTenant(http.HandlerFunc(c.handleFrameworks)))
	mux.Handle("GET /v1/controls", c.requireTenant(http.HandlerFunc(c.handleControls)))
	mux.Handle("GET /v1/controls/{id}", c.requireTenant(http.HandlerFunc(c.handleControl)))
	mux.Handle("POST /v1/check", c.requireTenant(http.HandlerFunc(c.handleCheck)))
	mux.Handle("GET /v1/findings", c.requireTenant(http.HandlerFunc(c.handleFindings)))
	mux.Handle("GET /v1/runs", c.requireTenant(http.HandlerFunc(c.handleListRuns)))
	mux.Handle("GET /v1/runs/{id}", c.requireTenant(http.HandlerFunc(c.handleGetRun)))
	mux.Handle("GET /v1/events", c.requireTenant(http.HandlerFunc(c.handleEvents)))

	return logging(mux)
}

// --- Middleware ---

// tenantCtxKey is the typed context key for the resolved tenant.
type tenantCtxKey struct{}

// TenantFromContext returns the tenant injected by requireTenant.
func TenantFromContext(ctx context.Context) (store.Tenant, bool) {
	t, ok := ctx.Value(tenantCtxKey{}).(store.Tenant)
	return t, ok
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

func (c *Concord) requireTenant(next http.Handler) http.Handler {
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
		tenant, err := c.Store.GetTenantByID(r.Context(), tok.TenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "tenant lookup failed")
			return
		}
		ctx := context.WithValue(r.Context(), tenantCtxKey{}, tenant)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bearerToken extracts the token from an `Authorization: Bearer <x>` header.
// The "Bearer " comparison is case-insensitive to match RFC 6750.
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

// --- Admin handlers ---

func (c *Concord) handleAdminCreateTenant(w http.ResponseWriter, r *http.Request) {
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
	tenant, err := c.Store.CreateTenant(r.Context(), body.Name, body.Slug)
	if err != nil {
		writeError(w, http.StatusConflict, "creating tenant: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, tenant)
}

func (c *Concord) handleAdminListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := c.Store.ListTenants(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tenants)
}

func (c *Concord) handleAdminCreateToken(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	tenant, err := c.Store.GetTenantBySlug(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no tenant with slug "+slug)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "`name` is required")
		return
	}
	tok, plain, err := c.Store.CreateToken(r.Context(), tenant.ID, body.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         tok.ID,
		"tenant_id":  tok.TenantID,
		"name":       tok.Name,
		"created_at": tok.CreatedAt,
		"token":      plain,
		"note":       "Save this token now — it cannot be retrieved later.",
	})
}

func (c *Concord) handleAdminListTokens(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	tenant, err := c.Store.GetTenantBySlug(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no tenant with slug "+slug)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	toks, err := c.Store.ListTokens(r.Context(), tenant.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toks)
}

func (c *Concord) handleAdminDeleteToken(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	tokenIDRaw := r.PathValue("tokenID")
	tokenID, err := uuid.Parse(tokenIDRaw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	tenant, err := c.Store.GetTenantBySlug(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no tenant with slug "+slug)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := c.Store.DeleteToken(r.Context(), tenant.ID, tokenID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Tenant handlers (controls library is global in v0) ---

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
// responds 202 Accepted with the run id. Clients poll GET /v1/runs/{id}
// to retrieve findings once the status reaches "succeeded" or "failed".
func (c *Concord) handleCheck(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "tenant missing from context")
		return
	}
	run, err := c.Store.CreateRun(r.Context(), tenant.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "creating run: "+err.Error())
		return
	}
	if err := c.worker.Enqueue(runJob{TenantID: tenant.ID, RunID: run.ID}); err != nil {
		// Mark the run failed so it doesn't sit forever in `pending` and
		// surface 503 so the client backs off.
		_ = c.Store.FailRun(context.Background(), run.ID, err.Error())
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	w.Header().Set("Location", "/v1/runs/"+run.ID.String())
	writeJSON(w, http.StatusAccepted, map[string]any{
		"run_id":    run.ID,
		"status":    string(store.RunPending),
		"poll_url":  "/v1/runs/" + run.ID.String(),
		"started_at": run.StartedAt,
	})
}

// handleFindings returns the most recent succeeded run's findings.
func (c *Concord) handleFindings(w http.ResponseWriter, r *http.Request) {
	tenant, _ := TenantFromContext(r.Context())
	runs, err := c.Store.ListRuns(r.Context(), tenant.ID, 20)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, r0 := range runs {
		if r0.Status != store.RunSucceeded {
			continue
		}
		full, err := c.Store.GetRun(r.Context(), tenant.ID, r0.ID)
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
	tenant, _ := TenantFromContext(r.Context())
	runs, err := c.Store.ListRuns(r.Context(), tenant.ID, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Strip findings/summary blobs from the list view; clients fetch detail per-run.
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
	tenant, _ := TenantFromContext(r.Context())
	runID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid run id")
		return
	}
	run, err := c.Store.GetRun(r.Context(), tenant.ID, runID)
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

// writeFindingsEnvelope renders a Run with parsed summary + findings JSON.
// Falls back to raw bytes if the persisted blobs are malformed.
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

// handleEvents streams Server-Sent Events for the authenticated tenant.
// One subscriber per HTTP connection. The handler returns when the client
// disconnects or the server flushes a pending close.
//
// Wire format (per SSE):
//
//	event: <kind>
//	data: <event JSON>
//	(blank line)
//
// A 15s heartbeat keeps proxy idle timeouts at bay.
func (c *Concord) handleEvents(w http.ResponseWriter, r *http.Request) {
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "tenant missing from context")
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
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx response buffering
	w.WriteHeader(http.StatusOK)

	ch, unsub := c.bus.Subscribe(tenant.ID, 32)
	defer unsub()

	// Opening prelude so the client knows the stream is live even before the
	// first event lands.
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
// response. Without this, type-assertion goes against statusRecorder itself
// rather than the underlying writer, and SSE 500s.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
