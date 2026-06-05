package operator

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

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
	fresh, err := h.store.GetUserByID(r.Context(), user.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, fresh)
}

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
