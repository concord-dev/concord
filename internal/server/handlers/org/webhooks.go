package org

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// webhookView is the JSON shape returned on list/get. Secret is intentionally
// stripped — the secret is shown ONCE at create time and never again.
type webhookView struct {
	ID          uuid.UUID  `json:"id"`
	URL         string     `json:"url"`
	EventKinds  []string   `json:"event_kinds"`
	Enabled     bool       `json:"enabled"`
	LastFiredAt *time.Time `json:"last_fired_at,omitempty"`
	LastStatus  *int       `json:"last_status,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func viewFromWebhook(wh store.Webhook) webhookView {
	kinds := wh.EventKinds
	if kinds == nil {
		kinds = []string{}
	}
	return webhookView{
		ID: wh.ID, URL: wh.URL, EventKinds: kinds, Enabled: wh.Enabled,
		LastFiredAt: wh.LastFiredAt, LastStatus: wh.LastStatus, LastError: wh.LastError,
		CreatedAt: wh.CreatedAt, UpdatedAt: wh.UpdatedAt,
	}
}

// isValidWebhookURL enforces the http/https scheme so we never POST to
// internal-net schemes (file://, gopher://) by accident.
func isValidWebhookURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

func (h *Handlers) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	hooks, err := h.store.ListWebhooks(r.Context(), p.Org.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]webhookView, 0, len(hooks))
	for _, wh := range hooks {
		out = append(out, viewFromWebhook(wh))
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (h *Handlers) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	var body struct {
		URL        string   `json:"url"`
		EventKinds []string `json:"event_kinds,omitempty"`
		Enabled    *bool    `json:"enabled,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.URL == "" {
		httpx.Error(w, http.StatusBadRequest, "`url` is required")
		return
	}
	if !isValidWebhookURL(body.URL) {
		httpx.Error(w, http.StatusBadRequest, "`url` must start with http:// or https://")
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	wh, secret, err := h.store.CreateWebhook(r.Context(), store.CreateWebhookParams{
		OrgID: p.Org.ID, URL: body.URL, EventKinds: body.EventKinds, Enabled: enabled,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "webhook.create",
		TargetType: "webhook",
		TargetID:   &wh.ID,
		Details:    map[string]any{"url": wh.URL, "event_kinds": wh.EventKinds, "enabled": wh.Enabled},
	})
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"webhook": viewFromWebhook(wh),
		"secret":  secret,
		"note":    "Save this secret now. It is required to verify the X-Concord-Signature header and cannot be retrieved again.",
	})
}

func (h *Handlers) GetWebhook(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	wh, err := h.store.GetWebhook(r.Context(), p.Org.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "webhook not found")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, viewFromWebhook(wh))
}

func (h *Handlers) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	var body struct {
		URL        *string   `json:"url,omitempty"`
		EventKinds *[]string `json:"event_kinds,omitempty"`
		Enabled    *bool     `json:"enabled,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.URL != nil && !isValidWebhookURL(*body.URL) {
		httpx.Error(w, http.StatusBadRequest, "`url` must start with http:// or https://")
		return
	}
	wh, err := h.store.UpdateWebhook(r.Context(), p.Org.ID, id, store.UpdateWebhookParams{
		URL: body.URL, EventKinds: body.EventKinds, Enabled: body.Enabled,
	})
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "webhook not found")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "webhook.update",
		TargetType: "webhook",
		TargetID:   &wh.ID,
		Details:    map[string]any{"url": wh.URL, "event_kinds": wh.EventKinds, "enabled": wh.Enabled},
	})
	httpx.JSON(w, http.StatusOK, viewFromWebhook(wh))
}

func (h *Handlers) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	if err := h.store.DeleteWebhook(r.Context(), p.Org.ID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "webhook not found")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "webhook.delete",
		TargetType: "webhook",
		TargetID:   &id,
	})
	w.WriteHeader(http.StatusNoContent)
}
