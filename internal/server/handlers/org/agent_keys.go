package org

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// agentKeyView is the JSON shape returned to clients. PublicKey is base64
// because raw bytes don't round-trip cleanly through JSON.
type agentKeyView struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	PublicKey       string     `json:"public_key"` // base64 (raw 32 bytes)
	CreatedByUserID *uuid.UUID `json:"created_by_user_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
}

func viewFromAgentKey(k store.AgentKey) agentKeyView {
	return agentKeyView{
		ID:              k.ID,
		Name:            k.Name,
		PublicKey:       base64.StdEncoding.EncodeToString(k.PublicKey),
		CreatedByUserID: k.CreatedByUserID,
		CreatedAt:       k.CreatedAt,
		LastUsedAt:      k.LastUsedAt,
	}
}

// ListAgentKeys returns active (non-revoked) keys for the org.
func (h *Handlers) ListAgentKeys(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	keys, err := h.store.ListAgentKeys(r.Context(), p.Org.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]agentKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, viewFromAgentKey(k))
	}
	httpx.JSON(w, http.StatusOK, out)
}

// CreateAgentKey registers a new Ed25519 public key. Body:
//
//	{"name": "ci-prod", "public_key": "<base64-32-bytes>"}
//
// The 32-byte length is checked on the wire so we never store a malformed
// key. A duplicate name within an org returns 409.
func (h *Handlers) CreateAgentKey(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	var body struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"` // base64
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" || body.PublicKey == "" {
		httpx.Error(w, http.StatusBadRequest, "`name` and `public_key` are required")
		return
	}
	pubBytes, err := base64.StdEncoding.DecodeString(body.PublicKey)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "`public_key` must be base64 (standard encoding)")
		return
	}
	if len(pubBytes) != 32 {
		httpx.Error(w, http.StatusBadRequest, "Ed25519 public key must be exactly 32 bytes")
		return
	}
	key, err := h.store.CreateAgentKey(r.Context(), p.Org.ID, body.Name, pubBytes, p.UserID)
	if err != nil {
		// Unique-name violations come up as a generic error; surface them as 409.
		httpx.Error(w, http.StatusConflict, err.Error())
		return
	}
	httpx.JSON(w, http.StatusCreated, viewFromAgentKey(key))
}

// RevokeAgentKey soft-deletes a key by ID.
func (h *Handlers) RevokeAgentKey(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid agent key id")
		return
	}
	if err := h.store.RevokeAgentKey(r.Context(), p.Org.ID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "agent key not found")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
