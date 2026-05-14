package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/store"
)

// overrideEnvelope is the JSON shape we return on GET/PUT; the raw bytes
// from the DB get decoded so the response is a real JSON object, not an
// escaped string.
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

func (c *Concord) handleListOverrides(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	rows, err := c.Store.ListControlOverrides(r.Context(), p.Org.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]overrideEnvelope, 0, len(rows))
	for _, co := range rows {
		out = append(out, envelopeFromOverride(co))
	}
	writeJSON(w, http.StatusOK, out)
}

func (c *Concord) handleGetOverride(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	id := r.PathValue("id")
	if !c.controlExists(id) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no control with id %q", id))
		return
	}
	co, err := c.Store.GetControlOverride(r.Context(), p.Org.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no override set for this control")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelopeFromOverride(co))
}

// handlePutOverride replaces the params for one control. The body shape is
// `{"params": {...}}` so the wire shape is symmetrical with the GET response.
func (c *Concord) handlePutOverride(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	id := r.PathValue("id")
	if !c.controlExists(id) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no control with id %q", id))
		return
	}
	var body struct {
		Params map[string]any `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Params == nil {
		writeError(w, http.StatusBadRequest,
			"`params` is required (pass {} to clear all values while keeping the override row)")
		return
	}
	raw, err := json.Marshal(body.Params)
	if err != nil {
		writeError(w, http.StatusBadRequest, "params is not encodable: "+err.Error())
		return
	}
	co, err := c.Store.UpsertControlOverride(r.Context(), p.Org.ID, id, raw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelopeFromOverride(co))
}

func (c *Concord) handleDeleteOverride(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	id := r.PathValue("id")
	if err := c.Store.DeleteControlOverride(r.Context(), p.Org.ID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no override set for this control")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
