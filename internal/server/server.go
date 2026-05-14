// Package server hosts Concord's HTTP API. v0 is single-tenant: every
// request operates on a single in-memory controls library loaded at startup.
// Multi-tenancy, persistent storage, and auth land in v1 and beyond.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/concord-dev/concord/internal/config"
	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/policy"
	"github.com/concord-dev/concord/internal/report"
	"github.com/concord-dev/concord/internal/runner"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Concord bundles the in-memory state every handler operates on. It is the
// natural seam between v0 (single-tenant, this struct lives once per process)
// and v1+ (per-tenant, looked up by request auth).
type Concord struct {
	Controls  []controls.Loaded
	Config    *config.Config
	Registry  *evidence.Registry
	OutputDir string
	Version   string

	mu sync.Mutex // guards the persisted last-run file
}

// Options is what the cmd-side wiring passes in to construct a server.
type Options struct {
	ControlsDir  string
	ConfigPath   string
	OutputDir    string
	FixturesOnly bool
	Registry     *evidence.Registry // optional; falls back to a fixtures-only registry
	Version      string
}

// NewConcord loads controls + config + registry from the supplied paths.
// Returns an error if the controls directory is empty so the operator notices
// at startup rather than discovering it via a confusing /v1/check response.
func NewConcord(opts Options) (*Concord, error) {
	if opts.ControlsDir == "" {
		opts.ControlsDir = "./controls"
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = "./concord.yaml"
	}
	if opts.OutputDir == "" {
		opts.OutputDir = ".concord"
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

	return &Concord{
		Controls:  loaded,
		Config:    cfg,
		Registry:  reg,
		OutputDir: opts.OutputDir,
		Version:   opts.Version,
	}, nil
}

// Router returns the mux wired with every v0 endpoint. Caller can wrap the
// returned handler with logging / CORS / auth middleware as needed.
func (c *Concord) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", c.handleHealth)
	mux.HandleFunc("GET /version", c.handleVersion)
	mux.HandleFunc("GET /v1/frameworks", c.handleFrameworks)
	mux.HandleFunc("GET /v1/controls", c.handleControls)
	mux.HandleFunc("GET /v1/controls/{id}", c.handleControl)
	mux.HandleFunc("POST /v1/check", c.handleCheck)
	mux.HandleFunc("GET /v1/findings", c.handleFindings)
	return logging(mux)
}

func (c *Concord) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (c *Concord) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  c.Version,
		"controls": len(c.Controls),
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

// handleCheck runs every control synchronously and returns the JSONReport
// envelope. For v0 this is appropriate — a few hundred ms per fixture run.
// When live collectors land and runs grow long, /v1/check moves to async +
// /v1/runs/{id}.
func (c *Concord) handleCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	rn := runner.New(policy.New(), c.Registry).SetParams(c.Config.Controls.Params)
	findings := rn.RunAll(ctx, c.Controls)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.persistFindings(findings); err != nil {
		writeError(w, http.StatusInternalServerError, "persisting findings: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, report.JSONReport{
		Summary:  report.Summarize(findings),
		Findings: findings,
	})
}

func (c *Concord) handleFindings(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := filepath.Join(c.OutputDir, "last-run.json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "no findings persisted yet — POST /v1/check first")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reading findings: "+err.Error())
		return
	}
	var findings []apiv1.Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		writeError(w, http.StatusInternalServerError, "parsing findings: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report.JSONReport{
		Summary:  report.Summarize(findings),
		Findings: findings,
	})
}

func (c *Concord) persistFindings(findings []apiv1.Finding) error {
	if err := os.MkdirAll(c.OutputDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(c.OutputDir, "last-run.json")
	raw, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// Last-resort error; headers are already written so we can't change them.
		_, _ = io.WriteString(w, fmt.Sprintf(`{"error":%q}`, err.Error()))
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// logging is a minimal request logger. Caller can swap in a structured logger
// (zap, slog) when telemetry requirements firm up.
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
