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


const readyDepTimeout = 2 * time.Second

type Limits struct {
	InviteAcceptIP limiter.Bucket // per source IP for POST /v1/invitations/accept
}

type Handlers struct {
	version  string
	controls []controls.Loaded
	store    *store.Store // needed for the trust-portal endpoint
	limits   Limits
}

func New(version string, ctrls []controls.Loaded, s *store.Store, limits Limits) *Handlers {
	return &Handlers{version: version, controls: ctrls, store: s, limits: limits}
}

func (h *Handlers) audit(r *http.Request, p store.RecordAuditParams) {
	if p.IP == "" {
		p.IP = httpx.ClientIP(r)
	}
	if p.UserAgent == "" {
		p.UserAgent = r.UserAgent()
	}
	if p.RequestID == "" {
		p.RequestID = logx.RequestID(r.Context())
	}
	h.store.RecordAudit(r.Context(), p)
}

func allow(w http.ResponseWriter, b limiter.Bucket, key string) bool {
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

func (h *Handlers) Health(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

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

func (h *Handlers) Version(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{
		"version":  h.version,
		"controls": len(h.controls),
	})
}

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
