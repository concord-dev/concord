package public

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/report"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func (h *Handlers) TrustPortal(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	org, err := h.store.GetOrganizationBySlug(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !org.TrustPortalEnabled) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	run, ok, err := h.latestSucceededRun(r, org.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}

	var findings []apiv1.Finding
	if len(run.Findings) > 0 {
		_ = json.Unmarshal(run.Findings, &findings)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	renderer := report.TrustPortalRenderer{OrgName: org.Name}
	if _, err := renderer.Render(w, findings); err != nil {
		return
	}
}

func (h *Handlers) latestSucceededRun(r *http.Request, orgID uuid.UUID) (store.Run, bool, error) {
	runs, err := h.store.ListRuns(r.Context(), orgID, 50)
	if err != nil {
		return store.Run{}, false, err
	}
	for _, run := range runs {
		if run.Status != store.RunSucceeded {
			continue
		}
		full, err := h.store.GetRun(r.Context(), orgID, run.ID)
		if err != nil {
			return store.Run{}, false, err
		}
		return full, true, nil
	}
	return store.Run{}, false, nil
}
