package org

import (
	"encoding/json"
	"net/http"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
)

type trustPortalSettings struct {
	Enabled bool `json:"enabled"`
	URL string `json:"url"`
}

func (h *Handlers) GetTrustPortalSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	httpx.JSON(w, http.StatusOK, trustPortalSettings{
		Enabled: p.Org.TrustPortalEnabled,
		URL:     trustPortalURL(r, p.Org.Slug),
	})
}

func (h *Handlers) PutTrustPortalSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Enabled == nil {
		httpx.Error(w, http.StatusBadRequest, "`enabled` is required (true or false)")
		return
	}
	updated, err := h.store.SetTrustPortalEnabled(r.Context(), p.Org.ID, *body.Enabled)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, trustPortalSettings{
		Enabled: updated.TrustPortalEnabled,
		URL:     trustPortalURL(r, updated.Slug),
	})
}

func trustPortalURL(r *http.Request, slug string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = fwd
	}
	return scheme + "://" + host + "/v1/orgs/" + slug + "/trust-portal"
}
