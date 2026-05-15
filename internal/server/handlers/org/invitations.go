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

// invitationView is the JSON shape returned for invitations. The plaintext
// token is *only* in the create-response (see createInvitationResult). Lists
// and gets never re-disclose it — same write-once pattern as API tokens.
type invitationView struct {
	ID         uuid.UUID  `json:"id"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	InvitedBy  *uuid.UUID `json:"invited_by,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func viewFromInvitation(inv store.Invitation) invitationView {
	return invitationView{
		ID: inv.ID, Email: inv.Email, Role: inv.RoleName,
		InvitedBy: inv.InvitedBy, ExpiresAt: inv.ExpiresAt,
		AcceptedAt: inv.AcceptedAt, RevokedAt: inv.RevokedAt,
		CreatedAt: inv.CreatedAt,
	}
}

// CreateInvitation mints a pending invitation for (email, role) on the
// current org. Returns the persisted invitation AND the plaintext accept
// token — the only time the caller ever sees the token. Subsequent reads
// return only metadata.
//
// Any prior pending invitation for the same (org, email) is silently
// revoked in the store; the partial-unique index would otherwise reject the
// insert and a re-invite is the common case.
func (h *Handlers) CreateInvitation(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
		TTL   string `json:"ttl,omitempty"` // optional Go duration string, defaults to 7d
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Email = strings.TrimSpace(body.Email)
	if body.Email == "" || body.Role == "" {
		httpx.Error(w, http.StatusBadRequest, "`email` and `role` are required")
		return
	}

	role, err := h.store.GetRoleByName(r.Context(), body.Role)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusBadRequest, "unknown role "+body.Role)
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	ttl := 7 * 24 * time.Hour
	if body.TTL != "" {
		parsed, perr := time.ParseDuration(body.TTL)
		if perr != nil || parsed <= 0 {
			httpx.Error(w, http.StatusBadRequest,
				"`ttl` must be a positive Go duration (e.g. \"24h\", \"168h\")")
			return
		}
		ttl = parsed
	}

	inv, token, err := h.store.CreateInvitation(r.Context(), store.CreateInvitationParams{
		OrgID: p.Org.ID, Email: body.Email, RoleID: role.ID, InvitedBy: p.UserID, TTL: ttl,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"invitation": viewFromInvitation(inv),
		"token":      token,
		"accept_url": acceptURL(r, token),
		"note": "Share the link with the invitee. The token is shown ONCE — " +
			"if lost, revoke this invitation and issue a new one.",
	})
}

// ListInvitations returns every pending invitation for the org. Accepted /
// revoked / expired rows are filtered out — operators interested in audit
// history should query the DB directly.
func (h *Handlers) ListInvitations(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	invs, err := h.store.ListPendingInvitations(r.Context(), p.Org.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]invitationView, 0, len(invs))
	for _, inv := range invs {
		out = append(out, viewFromInvitation(inv))
	}
	httpx.JSON(w, http.StatusOK, out)
}

// RevokeInvitation soft-deletes a pending invitation. ID is scoped to the
// caller's org; not-found is returned identically for "no such id" and
// "already accepted/revoked".
func (h *Handlers) RevokeInvitation(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid invitation id")
		return
	}
	if err := h.store.RevokeInvitation(r.Context(), p.Org.ID, id, p.UserID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "invitation not found")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// acceptURL builds an absolute URL the inviter can paste into an email.
// Mirrors the same X-Forwarded-Host/Proto logic as the trust-portal URL.
func acceptURL(r *http.Request, token string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = fwd
	}
	return scheme + "://" + host + "/v1/invitations/accept?token=" + token
}
