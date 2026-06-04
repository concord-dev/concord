package operator

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// ListAuditors returns every user with the cross-org is_auditor flag set.
// Powers the operator dashboard's "who can read everything" page so the
// platform team can review the auditor population periodically (a
// compliance requirement on its own — SOC 2 CC6.1 expects that the
// people with broad data access are reviewed at least annually).
func (h *Handlers) ListAuditors(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListAuditors(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if users == nil {
		users = []store.User{}
	}
	httpx.JSON(w, http.StatusOK, users)
}

// GrantAuditor flips the cross-org is_auditor flag for a user. Idempotent —
// re-granting an already-auditor user is fine. Operator-only — members
// of an organization cannot self-promote into auditor status.
//
// Body: `{ "user_id": "<uuid>" }` or `{ "email": "..." }`. Audit event
// "user.auditor.grant" is emitted regardless of idempotency so the trail
// reflects intent, not just state change.
func (h *Handlers) GrantAuditor(w http.ResponseWriter, r *http.Request) {
	user, ok := h.resolveAuditorTarget(w, r)
	if !ok {
		return
	}
	if err := h.store.SetUserAuditor(r.Context(), user.ID, true); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "user not found")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "user.auditor.grant",
		TargetType: "user",
		TargetID:   &user.ID,
		Details:    map[string]any{"email": user.Email},
	})
	// Re-fetch so the response reflects the post-update row (is_auditor=true)
	// rather than the pre-update copy we resolved above.
	fresh, err := h.store.GetUserByID(r.Context(), user.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, fresh)
}

// RevokeAuditor clears the is_auditor flag. Same idempotency + audit
// semantics as GrantAuditor. NOTE: the user's active sessions are NOT
// invalidated here — that's a separate operator-facing concern (we don't
// have a "revoke all sessions for user X" endpoint yet); if you need
// hard cutoff, follow this with a manual session purge.
func (h *Handlers) RevokeAuditor(w http.ResponseWriter, r *http.Request) {
	user, ok := h.resolveAuditorTarget(w, r)
	if !ok {
		return
	}
	if err := h.store.SetUserAuditor(r.Context(), user.ID, false); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "user not found")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "user.auditor.revoke",
		TargetType: "user",
		TargetID:   &user.ID,
		Details:    map[string]any{"email": user.Email},
	})
	w.WriteHeader(http.StatusNoContent)
}

// resolveAuditorTarget reads `user_id` or `email` from the body and
// returns the matching user. Mirrors the resolution semantics of
// lookupUser but takes its inputs from the JSON body rather than a URL
// param, which fits how the operator dashboard wires its forms.
func (h *Handlers) resolveAuditorTarget(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	var body struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return store.User{}, false
	}
	if body.UserID == "" && body.Email == "" {
		httpx.Error(w, http.StatusBadRequest, "either `user_id` or `email` is required")
		return store.User{}, false
	}
	if body.UserID != "" {
		id, err := uuid.Parse(body.UserID)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid user_id")
			return store.User{}, false
		}
		u, err := h.store.GetUserByID(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "user not found")
			return store.User{}, false
		}
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return store.User{}, false
		}
		return u, true
	}
	u, err := h.store.GetUserByEmail(r.Context(), body.Email)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "user not found")
		return store.User{}, false
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return store.User{}, false
	}
	return u, true
}
