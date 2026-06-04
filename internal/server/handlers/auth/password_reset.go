package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/notify/mail"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// RequestPasswordReset handles `POST /v1/auth/password-reset`.
//
// Always returns 200 with `{"status":"ok"}` — even when the email is unknown
// — to avoid leaking which addresses have accounts (user-enumeration via
// the response is a classic mistake). The reset token, when minted, is
// logged at info level; production deployments should send it via email and
// stop printing it.
//
// Body: { "email": "..." }
func (h *Handlers) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	if !allow(w, h.limits.PWResetIP, httpx.ClientIP(r)) {
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Email = strings.TrimSpace(body.Email)
	if body.Email == "" {
		httpx.Error(w, http.StatusBadRequest, "`email` is required")
		return
	}

	// Always answer 200, regardless of whether the email exists.
	defer httpx.JSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"note":   "If an account exists for that email, a reset link has been issued.",
	})

	log := logx.FromContext(r.Context())
	user, err := h.store.GetUserByEmail(r.Context(), body.Email)
	if errors.Is(err, store.ErrNotFound) {
		return // silently — no enumeration leak
	}
	if err != nil {
		log.Error("password reset lookup failed",
			slog.String("email", body.Email),
			slog.String("err", err.Error()))
		return
	}

	_, token, err := h.store.CreatePasswordReset(r.Context(), store.CreatePasswordResetParams{
		UserID:      user.ID,
		RequesterIP: httpx.ClientIP(r),
		RequesterUA: r.UserAgent(),
	})
	if err != nil {
		log.Error("password reset insert failed",
			slog.String("user_id", user.ID.String()),
			slog.String("err", err.Error()))
		return
	}
	confirmURL := resetBaseURL(r) + "/v1/auth/password-reset/confirm?token=" + token
	log.Info("password reset issued",
		slog.String("user_id", user.ID.String()),
		slog.String("email", user.Email))
	// Deliver via mail asynchronously so SMTP latency / failures never
	// extend the HTTP response time on a hot endpoint. The LogMailer
	// fallback prints the URL — sufficient for local dev — so this also
	// keeps the "I forgot, show me the URL" workflow alive without a relay.
	h.goAsync(func() { sendPasswordResetEmail(h.mailer, user.Email, confirmURL) })
	h.audit(r, store.RecordAuditParams{
		ActorKind:   store.AuditActorUnauthenticated,
		Action:      "auth.password_reset.request",
		TargetType:  "user",
		TargetID:    &user.ID,
		Details:     map[string]any{"email": user.Email},
	})
}

// sendPasswordResetEmail composes + delivers the reset-link email. Runs
// off the request goroutine — we don't want SMTP latency on the response
// path. Failures are loud (slog) but never propagated: the caller already
// returned 200 to the user (anti-enumeration) and we can't unwind that.
//
// When mailer is nil (handler constructed without one — tests do this),
// degrade to a slog line that carries the URL, so the dev still has a way
// to complete the flow.
func sendPasswordResetEmail(mailer mail.Mailer, to, confirmURL string) {
	if mailer == nil {
		slog.Info("password reset: no mailer configured; reset link follows",
			slog.String("to", to),
			slog.String("confirm_url", confirmURL))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	body := fmt.Sprintf(
		"Hi,\n\nWe received a request to reset the password for the Concord account associated with this email.\n\n"+
			"Open the link below to choose a new password. The link is single-use and expires shortly.\n\n%s\n\n"+
			"If you didn't request this, you can ignore this email — your password won't change.\n\n— Concord",
		confirmURL,
	)
	if err := mailer.Send(ctx, mail.Message{
		To:      to,
		Subject: "Reset your Concord password",
		Body:    body,
	}); err != nil {
		slog.Error("password reset: mail delivery failed",
			slog.String("to", to),
			slog.String("err", err.Error()))
	}
}

// ConfirmPasswordReset handles `POST /v1/auth/password-reset/confirm`.
//
// Body: { "token": "...", "new_password": "..." }
//
// On success, the user's password is updated, this token is consumed, every
// active session for the user is revoked, and a fresh session is minted so
// the caller is immediately logged in.
func (h *Handlers) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	if !allow(w, h.limits.PWConfirmIP, httpx.ClientIP(r)) {
		return
	}
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Token = strings.TrimSpace(body.Token)
	if body.Token == "" || body.NewPassword == "" {
		httpx.Error(w, http.StatusBadRequest, "`token` and `new_password` are both required")
		return
	}

	user, err := h.store.ConsumePasswordReset(r.Context(), store.ConsumePasswordResetParams{
		Token:       body.Token,
		NewPassword: body.NewPassword,
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, store.ErrPasswordResetExpired):
		httpx.Error(w, http.StatusGone, "reset link expired — request a new one")
		return
	case err != nil:
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess, plain, err := h.store.CreateSession(r.Context(), user.ID, h.sessionTTL,
		httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		ActorKind:   store.AuditActorUser,
		ActorUserID: &user.ID,
		Action:      "auth.password_reset.confirm",
		TargetType:  "user",
		TargetID:    &user.ID,
	})
	httpx.JSON(w, http.StatusOK, map[string]any{
		"session_id": sess.ID,
		"token":      plain,
		"expires_at": sess.ExpiresAt,
		"user":       user,
		"note":       "All previous sessions for this user have been revoked.",
	})
}

// resetBaseURL is the scheme://host the operator can paste into an email.
// Mirrors trustPortalURL — honours X-Forwarded-Proto/Host so a TLS-
// terminating proxy upstream produces sensible https://… URLs.
func resetBaseURL(r *http.Request) string {
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
	return scheme + "://" + host
}
