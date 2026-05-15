// Package public hosts the unauthenticated endpoints: /healthz, /version,
// /openapi.yaml, /docs, and the public trust portal at
// /v1/orgs/{slug}/trust-portal (gated by an opt-in flag per org).
package public

import (
	"io"
	"net/http"

	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/server/openapi"
	"github.com/concord-dev/concord/internal/store"
)

// Handlers bundles dependencies for the public route group.
type Handlers struct {
	version  string
	controls []controls.Loaded
	store    *store.Store // needed for the trust-portal endpoint
}

// New constructs Handlers with the supplied build metadata, loaded controls,
// and a Store. The Store is read-only from this subpackage — only the trust
// portal handler reaches into it, and only to load org metadata + the latest
// succeeded run.
func New(version string, ctrls []controls.Loaded, s *store.Store) *Handlers {
	return &Handlers{version: version, controls: ctrls, store: s}
}

// Health is the liveness probe (e.g. for Kubernetes / load balancers).
func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "ok"})
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
