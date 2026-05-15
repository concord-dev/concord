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

// TrustPortal renders an org's public compliance snapshot: a self-contained
// HTML page sourced from the org's most recent succeeded run. The route is
// public (no auth), but disabled by default — orgs opt in by flipping
// `trust_portal_enabled` via the org-API settings endpoint.
//
// 404 responses are deliberately identical for "no such org" and "portal
// disabled" so the public endpoint can't be used to enumerate which slugs
// exist on the deployment.
//
// 404 is also returned when the portal is enabled but no run has succeeded
// yet — the empty-state UX belongs upstream (a frontend can show "compliance
// snapshot pending"); we don't fabricate one server-side.
func (h *Handlers) TrustPortal(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	org, err := h.store.GetOrganizationBySlug(r.Context(), slug)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !org.TrustPortalEnabled) {
		// Same response either way — see the godoc above.
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
	// Short cache: dashboards expect near-live data after a manual /check.
	// 60s is enough to absorb a refresh storm without staleness complaints.
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	renderer := report.TrustPortalRenderer{OrgName: org.Name}
	if _, err := renderer.Render(w, findings); err != nil {
		// Headers already written; logging is the best we can do.
		// httpx.Error would corrupt the response.
		return
	}
}

// latestSucceededRun returns the most recent run with status "succeeded".
// Returns ok=false (no error) when no such run exists yet.
//
// Implementation note: ListRuns(limit=50) is the cheapest path that doesn't
// require a new dedicated query. If "no successful run in last 50" becomes a
// real failure mode (busy orgs with constant failures), promote to a
// `GetLatestRunByStatus` store method.
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
