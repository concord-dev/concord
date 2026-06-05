package org

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	resp := map[string]any{
		"organization": p.Org,
		"token_id":     p.TokenID,
		"user_id":      p.UserID,
	}
	if p.UserID != nil {
		perms, err := h.store.UserPermissions(r.Context(), *p.UserID, p.Org.ID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp["permissions"] = perms
	}
	httpx.JSON(w, http.StatusOK, resp)
}

func (h *Handlers) Frameworks(w http.ResponseWriter, _ *http.Request) {
	type entry struct {
		Framework string `json:"framework"`
		Controls  int    `json:"controls"`
	}
	counts := make(map[string]int)
	for _, l := range h.controls {
		counts[l.Control.Metadata.Framework]++
	}
	out := make([]entry, 0, len(counts))
	for fw, n := range counts {
		out = append(out, entry{Framework: fw, Controls: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Framework < out[j].Framework })
	httpx.JSON(w, http.StatusOK, out)
}

func (h *Handlers) Controls(w http.ResponseWriter, r *http.Request) {
	framework := r.URL.Query().Get("framework")
	out := make([]apiv1.Control, 0, len(h.controls))
	for _, l := range h.controls {
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
	httpx.JSON(w, http.StatusOK, out)
}

func (h *Handlers) Control(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target := strings.ToLower(id)
	for _, l := range h.controls {
		if strings.ToLower(l.Control.Metadata.ID) == target {
			httpx.JSON(w, http.StatusOK, l.Control)
			return
		}
	}
	httpx.Error(w, http.StatusNotFound, fmt.Sprintf("no control with id %q", id))
}
