package public

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// SessionTTL is the lifetime of sessions auto-issued on accept. Mirrors the
// server-wide default; not configurable per request because there's no
// authenticated caller to drive it.
const SessionTTL = 24 * time.Hour

// PreviewInvitation returns the email + org slug + role behind a token so a
// frontend can render "Join {OrgName} as {role}?" before the user commits.
// No auth — the token is the proof.
//
// 404 collapses unknown / revoked / accepted into one response; 410 is used
// when the token exists but expired (the message is actionable: "ask for a
// fresh invitation").
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
	// Hint the frontend whether the invitee already has a Concord account.
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

// AcceptInvitation completes the flow:
//   - if the invitee's email is new to Concord, create a user with the
//     supplied first/last/password
//   - either way, attach the user to the org with the invited role
//   - mint a session token so the caller is logged in immediately
//
// Body shape:
//
//	{ "token": "...", "first_name": "...", "last_name": "...", "password": "..." }
//
// For existing accounts first/last/password are ignored (they keep their
// credentials; this accept just gains them org membership).
func (h *Handlers) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	if !allow(w, h.limits.InviteAcceptIP, clientIP(r)) {
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
		// Argues from message: "first_name, last_name, and password are required"
		// belongs in 400; everything else in 500.
		if strings.Contains(err.Error(), "required") {
			httpx.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Issue a session so the invitee is logged in immediately. New users
	// don't have any other credential they can authenticate with yet — this
	// is the only way they'll see the dashboard after clicking the link.
	sess, plain, err := h.store.CreateSession(r.Context(), res.User.ID, SessionTTL,
		clientIP(r), r.UserAgent())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	org, err := h.store.GetOrganizationByID(r.Context(), res.Invitation.OrgID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit as the now-attached user — by the time we get here the invitation
	// is consumed and the user is a real member of the org.
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

// clientIP picks the leftmost X-Forwarded-For entry when behind a proxy,
// falling back to RemoteAddr's host portion. Uses net.SplitHostPort so IPv6
// literals (`[::1]:8080`) lose their brackets — Postgres `inet` rejects
// bracketed addresses and we store this column unconditionally.
//
// Duplicated from handlers/auth/auth.go to keep the public subpackage free of
// an internal auth-package dependency.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
