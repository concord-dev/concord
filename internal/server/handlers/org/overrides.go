package org

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

type overrideEnvelope struct {
	ID        uuid.UUID      `json:"id"`
	ControlID string         `json:"control_id"`
	Params    map[string]any `json:"params"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func envelopeFromOverride(co store.ControlOverride) overrideEnvelope {
	var params map[string]any
	if len(co.Params) > 0 {
		_ = json.Unmarshal(co.Params, &params)
	}
	return overrideEnvelope{
		ID: co.ID, ControlID: co.ControlID, Params: params,
		CreatedAt: co.CreatedAt, UpdatedAt: co.UpdatedAt,
	}
}

func (h *Handlers) ListOverrides(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	rows, err := h.store.ListControlOverrides(r.Context(), p.Org.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]overrideEnvelope, 0, len(rows))
	for _, co := range rows {
		out = append(out, envelopeFromOverride(co))
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (h *Handlers) GetOverride(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	id := r.PathValue("id")
	if !h.controlExists(id) {
		httpx.Error(w, http.StatusNotFound, fmt.Sprintf("no control with id %q", id))
		return
	}
	co, err := h.store.GetControlOverride(r.Context(), p.Org.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "no override set for this control")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, envelopeFromOverride(co))
}

func (h *Handlers) PutOverride(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	id := r.PathValue("id")
	if !h.controlExists(id) {
		httpx.Error(w, http.StatusNotFound, fmt.Sprintf("no control with id %q", id))
		return
	}
	var body struct {
		Params map[string]any `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Params == nil {
		httpx.Error(w, http.StatusBadRequest,
			"`params` is required (pass {} to clear all values while keeping the override row)")
		return
	}
	raw, err := json.Marshal(body.Params)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "params is not encodable: "+err.Error())
		return
	}
	co, err := h.store.UpsertControlOverride(r.Context(), p.Org.ID, id, raw)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "control_override.upsert",
		TargetType: "control_override",
		TargetID:   &co.ID,
		Details:    map[string]any{"control_id": id, "params": body.Params},
	})
	httpx.JSON(w, http.StatusOK, envelopeFromOverride(co))
}

func (h *Handlers) DeleteOverride(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	id := r.PathValue("id")
	if err := h.store.DeleteControlOverride(r.Context(), p.Org.ID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "no override set for this control")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "control_override.delete",
		TargetType: "control_override",
		Details:    map[string]any{"control_id": id},
	})
	w.WriteHeader(http.StatusNoContent)
}
