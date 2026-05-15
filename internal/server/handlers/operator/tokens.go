package operator

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// CreateToken mints a new API token for an org. The plaintext is returned
// ONCE; subsequent reads only see metadata.
func (h *Handlers) CreateToken(w http.ResponseWriter, r *http.Request) {
	org, ok := h.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	var body struct {
		Name           string `json:"name"`
		CreatedByEmail string `json:"created_by_email,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" {
		httpx.Error(w, http.StatusBadRequest, "name is required")
		return
	}
	createdBy, ok := h.resolveTokenCreator(w, r, body.CreatedByEmail)
	if !ok {
		return
	}
	tok, plain, err := h.store.CreateAPIToken(r.Context(), org.ID, body.Name, createdBy)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "token.create",
		OrgID:      &org.ID,
		TargetType: "api_token",
		TargetID:   &tok.ID,
		Details:    map[string]any{"name": tok.Name},
	})
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"id":                 tok.ID,
		"org_id":             tok.OrgID,
		"name":               tok.Name,
		"created_by_user_id": tok.CreatedByUserID,
		"created_at":         tok.CreatedAt,
		"token":              plain,
		"note":               "Save this token now — it cannot be retrieved later.",
	})
}

func (h *Handlers) resolveTokenCreator(w http.ResponseWriter, r *http.Request, email string) (*uuid.UUID, bool) {
	if email == "" {
		return nil, true
	}
	u, err := h.store.GetUserByEmail(r.Context(), email)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "created_by_email not found")
		return nil, false
	}
	return &u.ID, true
}

func (h *Handlers) ListTokens(w http.ResponseWriter, r *http.Request) {
	org, ok := h.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	toks, err := h.store.ListAPITokens(r.Context(), org.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, toks)
}

func (h *Handlers) RevokeToken(w http.ResponseWriter, r *http.Request) {
	org, ok := h.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	tokenID, err := uuid.Parse(r.PathValue("tokenID"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid token id")
		return
	}
	if err := h.store.RevokeAPIToken(r.Context(), org.ID, tokenID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "token not found")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "token.revoke",
		OrgID:      &org.ID,
		TargetType: "api_token",
		TargetID:   &tokenID,
	})
	w.WriteHeader(http.StatusNoContent)
}
