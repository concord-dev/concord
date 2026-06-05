package public

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

const SessionTTL = 24 * time.Hour

func (h *Handlers) PreviewInvitation(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		httpx.Error(w, http.StatusBadRequest, "`token` query param is required")
		return
	}
	inv, err := h.store.GetInvitationByToken(r.Context(), token)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if time.Now().After(inv.ExpiresAt) {
		httpx.Error(w, http.StatusGone, "invitation expired — ask for a fresh one")
		return
	}
	org, err := h.store.GetOrganizationByID(r.Context(), inv.OrgID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, lookupErr := h.store.GetUserByEmail(r.Context(), inv.Email)
	needsAccount := errors.Is(lookupErr, store.ErrNotFound)

	httpx.JSON(w, http.StatusOK, map[string]any{
		"email":         inv.Email,
		"role":          inv.RoleName,
		"organization":  map[string]any{"slug": org.Slug, "name": org.Name},
		"expires_at":    inv.ExpiresAt,
		"needs_account": needsAccount,
	})
}

func (h *Handlers) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	if !allow(w, h.limits.InviteAcceptIP, httpx.ClientIP(r)) {
		return
	}
	var body struct {
		Token     string `json:"token"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Password  string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Token = strings.TrimSpace(body.Token)
	if body.Token == "" {
		httpx.Error(w, http.StatusBadRequest, "`token` is required")
		return
	}

	res, err := h.store.AcceptInvitation(r.Context(), store.AcceptInvitationParams{
		Token:     body.Token,
		FirstName: strings.TrimSpace(body.FirstName),
		LastName:  strings.TrimSpace(body.LastName),
		Password:  body.Password,
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, store.ErrInvitationExpired):
		httpx.Error(w, http.StatusGone, "invitation expired — ask for a fresh one")
		return
	case err != nil:
		if strings.Contains(err.Error(), "required") {
			httpx.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess, plain, err := h.store.CreateSession(r.Context(), res.User.ID, SessionTTL,
		httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	org, err := h.store.GetOrganizationByID(r.Context(), res.Invitation.OrgID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit(r, store.RecordAuditParams{
		ActorKind:   store.AuditActorUser,
		ActorUserID: &res.User.ID,
		OrgID:       &org.ID,
		Action:      "invitation.accept",
		TargetType:  "invitation",
		TargetID:    &res.Invitation.ID,
		Details:     map[string]any{"role": res.Invitation.RoleName, "created_user": res.CreatedUser},
	})

	httpx.JSON(w, http.StatusOK, map[string]any{
		"session_id":     sess.ID,
		"token":          plain,
		"expires_at":     sess.ExpiresAt,
		"user":           res.User,
		"organization":   map[string]any{"slug": org.Slug, "name": org.Name},
		"role":           res.Invitation.RoleName,
		"created_user":   res.CreatedUser,
		"assigned_role":  res.AssignedRole,
	})
}

