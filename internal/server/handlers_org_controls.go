package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// handleOrgMe reports the org resolved from the calling token, the auth
// surface used (token vs session), and (for session users) the resolved
// permission list — handy for dashboards rendering "what can I do here?"
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

// handleFrameworks returns the distinct frameworks loaded into the server,
// with per-framework control counts.
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

// handleControls lists every control, optionally filtered by ?framework=.
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

// handleControl fetches a single control by id (case-insensitive).
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
