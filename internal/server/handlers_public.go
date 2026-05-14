package server

import (
	"io"
	"net/http"

	"github.com/concord-dev/concord/internal/server/openapi"
)

// handleHealth is the liveness probe (e.g. for Kubernetes / load balancers).
func (c *Concord) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleVersion exposes build metadata + the size of the loaded controls library.
func (c *Concord) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  c.Version,
		"controls": len(c.Controls),
	})
}

// handleOpenAPI serves the hand-maintained spec verbatim. Public — anyone
// can fetch the API contract without auth, same as the routes it describes.
func (c *Concord) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	spec, err := openapi.SpecYAML()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(spec)
}

// handleDocs serves a minimal HTML page that loads Swagger UI from a CDN and
// points it at /openapi.yaml. Zero build steps; the entire frontend is one
// static page.
func (c *Concord) handleDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, docsHTML)
}

// docsHTML is the inline Swagger UI shim. Kept tiny and CDN-loaded so the
// server binary stays a single artifact with no embedded JS.
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
