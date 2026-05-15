// Package public hosts the unauthenticated endpoints: /healthz, /version,
// /openapi.yaml, /docs, and the public trust portal at
// /v1/orgs/{slug}/trust-portal (gated by an opt-in flag per org).
package public

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/server/limiter"
	"github.com/concord-dev/concord/internal/server/openapi"
	"github.com/concord-dev/concord/internal/store"
)

// clientIP is declared in invitations.go; the audit helper above relies on it
// (Go's package-level functions can be cross-referenced freely between files).

// readyDepTimeout caps each dep-check probe. Long enough to tolerate a slow
// initial connection across a region, short enough that piling-up readiness
// probes can't accumulate goroutines if a dep is genuinely down.
const readyDepTimeout = 2 * time.Second

// Limits is the bundle of rate-limit buckets the public handlers consult.
// Each may be nil — disabling that gate.
type Limits struct {
	InviteAcceptIP *limiter.Bucket // per source IP for POST /v1/invitations/accept
}

// Handlers bundles dependencies for the public route group.
type Handlers struct {
	version  string
	controls []controls.Loaded
	store    *store.Store // needed for the trust-portal endpoint
	limits   Limits
}

// New constructs Handlers with the supplied build metadata, loaded controls,
// a Store, and rate limits. The Store is read-only from this subpackage —
// only the trust portal handler reaches into it, and only to load org
// metadata + the latest succeeded run.
func New(version string, ctrls []controls.Loaded, s *store.Store, limits Limits) *Handlers {
	return &Handlers{version: version, controls: ctrls, store: s, limits: limits}
}

// audit fills in request-scoped forensic fields and delegates to
// store.RecordAudit. The caller must populate ActorKind / actor IDs since
// the public handlers serve unauthenticated callers in some flows (and a
// post-accept invitation in others where the user is freshly attached).
func (h *Handlers) audit(r *http.Request, p store.RecordAuditParams) {
	if p.IP == "" {
		p.IP = clientIP(r)
	}
	if p.UserAgent == "" {
		p.UserAgent = r.UserAgent()
	}
	if p.RequestID == "" {
		p.RequestID = logx.RequestID(r.Context())
	}
	h.store.RecordAudit(r.Context(), p)
}

// allow is the per-handler 429 gate. Nil bucket = disabled.
func allow(w http.ResponseWriter, b *limiter.Bucket, key string) bool {
	if b == nil {
		return true
	}
	ok, retryAfter := b.Allow(key)
	if ok {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	httpx.Error(w, http.StatusTooManyRequests, "rate limit exceeded; retry shortly")
	return false
}

// Health is the liveness probe (e.g. for Kubernetes / load balancers). It
// deliberately never touches downstream dependencies — restarting the process
// can't repair a downed database, and a livenessProbe that fails on DB blips
// would just crash-loop the server. Use /readyz for dep-aware checks.
func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// Ready is the readiness probe: returns 200 only when every dep is reachable.
// On failure the response is 503 with a per-dep breakdown so an operator can
// page-load the endpoint and see which subsystem is down. K8s readinessProbes
// should poll this; load balancers should drop the pod from rotation while
// it's failing.
func (h *Handlers) Ready(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	allOK := true

	dbCtx, cancel := context.WithTimeout(r.Context(), readyDepTimeout)
	defer cancel()
	if err := h.store.Pool().Ping(dbCtx); err != nil {
		checks["database"] = err.Error()
		allOK = false
		logx.FromContext(r.Context()).Warn("readiness check failed",
			slog.String("dep", "database"),
			slog.String("err", err.Error()))
	} else {
		checks["database"] = "ok"
	}

	body := map[string]any{"checks": checks}
	if allOK {
		body["status"] = "ok"
		httpx.JSON(w, http.StatusOK, body)
		return
	}
	body["status"] = "degraded"
	httpx.JSON(w, http.StatusServiceUnavailable, body)
}

// Version exposes build metadata + the loaded controls count.
func (h *Handlers) Version(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{
		"version":  h.version,
		"controls": len(h.controls),
	})
}

// OpenAPI serves the hand-maintained spec verbatim.
func (h *Handlers) OpenAPI(w http.ResponseWriter, _ *http.Request) {
	spec, err := openapi.SpecYAML()
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(spec)
}

// Docs serves a minimal HTML page that loads Swagger UI from a CDN and points
// it at /openapi.yaml.
func (h *Handlers) Docs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, docsHTML)
}

const docsHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Concord API</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: "/openapi.yaml",
      dom_id: "#swagger-ui",
      deepLinking: true,
      persistAuthorization: true,
    });
  </script>
</body>
</html>
`
