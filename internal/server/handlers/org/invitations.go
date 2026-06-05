package org

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/notify/mail"
	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

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
	h.audit(r, store.RecordAuditParams{
		Action:     "invitation.create",
		TargetType: "invitation",
		TargetID:   &inv.ID,
		Details:    map[string]any{"email": inv.Email, "role": inv.RoleName},
	})
	h.goAsync(func() {
		sendInvitationEmail(h.mailer, inv.Email, p.Org.Name, inv.RoleName, acceptURL(r, token))
	})
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"invitation": viewFromInvitation(inv),
		"token":      token,
		"accept_url": acceptURL(r, token),
		"note": "Share the link with the invitee. The token is shown ONCE — " +
			"if lost, revoke this invitation and issue a new one.",
	})
}

func sendInvitationEmail(mailer mail.Mailer, to, orgName, role, acceptURL string) {
	if mailer == nil {
		slog.Info("invitation: no mailer configured; accept link follows",
			slog.String("to", to),
			slog.String("org", orgName),
			slog.String("accept_url", acceptURL))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	body := fmt.Sprintf(
		"Hi,\n\nYou've been invited to join the %q organization on Concord as a %s.\n\n"+
			"Open the link below to accept. If you don't already have a Concord account, "+
			"you'll be prompted to set a password when you click through.\n\n%s\n\n"+
			"If you weren't expecting this, you can safely ignore the email — the invitation will expire.\n\n— Concord",
		orgName, role, acceptURL,
	)
	if err := mailer.Send(ctx, mail.Message{
		To:      to,
		Subject: fmt.Sprintf("You're invited to %s on Concord", orgName),
		Body:    body,
	}); err != nil {
		slog.Error("invitation: mail delivery failed",
			slog.String("to", to),
			slog.String("err", err.Error()))
	}
}

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
	h.audit(r, store.RecordAuditParams{
		Action:     "invitation.revoke",
		TargetType: "invitation",
		TargetID:   &id,
	})
	w.WriteHeader(http.StatusNoContent)
}

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
