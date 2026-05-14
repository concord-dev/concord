package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/store"
)

// handleAdminCreateToken mints a new API token for an org. The plaintext is
// returned ONCE; subsequent reads only see metadata.
func (c *Concord) handleAdminCreateToken(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	var body struct {
		Name           string `json:"name"`
		CreatedByEmail string `json:"created_by_email,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	createdBy, ok := c.resolveTokenCreator(w, r, body.CreatedByEmail)
	if !ok {
		return
	}
	tok, plain, err := c.Store.CreateAPIToken(r.Context(), org.ID, body.Name, createdBy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":                 tok.ID,
		"org_id":             tok.OrgID,
		"name":               tok.Name,
		"created_by_user_id": tok.CreatedByUserID,
		"created_at":         tok.CreatedAt,
		"token":              plain,
		"note":               "Save this token now — it cannot be retrieved later.",
	})
}

// resolveTokenCreator looks up the creator email if provided. Empty email →
// nil pointer (token has no human attribution).
func (c *Concord) resolveTokenCreator(w http.ResponseWriter, r *http.Request, email string) (*uuid.UUID, bool) {
	if email == "" {
		return nil, true
	}
	u, err := c.Store.GetUserByEmail(r.Context(), email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "created_by_email not found")
		return nil, false
	}
	return &u.ID, true
}

func (c *Concord) handleAdminListTokens(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	toks, err := c.Store.ListAPITokens(r.Context(), org.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toks)
}

func (c *Concord) handleAdminRevokeToken(w http.ResponseWriter, r *http.Request) {
	org, ok := c.lookupOrgBySlug(w, r, r.PathValue("slug"))
	if !ok {
		return
	}
	tokenID, err := uuid.Parse(r.PathValue("tokenID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	if err := c.Store.RevokeAPIToken(r.Context(), org.ID, tokenID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
