// Package auth hosts the session-lifecycle and session-scoped endpoints:
// /v1/auth/login, /v1/auth/logout, /v1/me, /v1/me/orgs.
package auth

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/notify/mail"
	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/server/limiter"
	"github.com/concord-dev/concord/internal/store"
)

// Limits is the bundle of rate-limit buckets the auth handlers consult.
// Each may be nil — in which case that gate is disabled. The server wires
// real buckets; tests can pass an empty struct to disable limiting.
type Limits struct {
	LoginIP     *limiter.Bucket // per source IP for POST /v1/auth/login
	LoginEmail  *limiter.Bucket // per email for POST /v1/auth/login (anti-stuffing)
	PWResetIP   *limiter.Bucket // per source IP for POST /v1/auth/password-reset
	PWConfirmIP *limiter.Bucket // per source IP for POST /v1/auth/password-reset/confirm
	MFASubmitIP *limiter.Bucket // per source IP for POST /v1/auth/login/mfa
}

// mfaChallengeTTL is the lifetime of a challenge token returned by Login.
// Long enough that a slow user can find their phone, short enough that a
// leaked token in an access log isn't usefully exploitable.
const mfaChallengeTTL = 5 * time.Minute

// Handlers bundles dependencies for the auth route group.
type Handlers struct {
	store      *store.Store
	sessionTTL time.Duration
	limits     Limits
	mailer     mail.Mailer
}

// New constructs Handlers with the given Store, session lifetime, rate
// limits, and mailer. Pass an empty Limits{} to disable all gates (tests
// do this); pass nil for the mailer to drop email delivery entirely
// (handlers fall back to logging the URL).
func New(s *store.Store, sessionTTL time.Duration, limits Limits, mailer mail.Mailer) *Handlers {
	return &Handlers{store: s, sessionTTL: sessionTTL, limits: limits, mailer: mailer}
}

// Login exchanges email + password for a session token. Same error message for
// unknown email and bad password to prevent user enumeration.
//
// Rate-limited per source IP and per email — the IP gate stops password
// spraying from one host, the email gate stops credential stuffing that
// rotates IPs against a single account. The IP check runs before JSON
// parse so an exhausted attacker can't make the server burn cycles on
// decoding.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	if !allow(w, h.limits.LoginIP, clientIP(r)) {
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Email == "" || body.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "email and password are required")
		return
	}
	if !allow(w, h.limits.LoginEmail, strings.ToLower(strings.TrimSpace(body.Email))) {
		return
	}
	user, err := h.store.VerifyUserPassword(r.Context(), body.Email, body.Password)
	if errors.Is(err, store.ErrNotFound) {
		// Record the failed attempt against the email the caller offered.
		// Unauthenticated: the actor was never proven, so actor_user_id stays
		// nil. The email lands in details so forensic queries can pivot on it.
		h.audit(r, store.RecordAuditParams{
			ActorKind: store.AuditActorUnauthenticated,
			Action:    "auth.login.failure",
			Details:   map[string]any{"email": body.Email, "reason": "invalid_credentials"},
		})
		httpx.Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	// MFA branch: if the user has a verified TOTP secret, do NOT mint a
	// session yet — return a short-lived challenge token instead. The
	// caller hits /v1/auth/login/mfa with the challenge + a TOTP code (or
	// a recovery code) to complete the login.
	enrolled, err := h.store.IsUserMFAEnrolled(r.Context(), user.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if enrolled {
		_, challengeToken, err := h.store.CreateMFAChallenge(
			r.Context(), user.ID, clientIP(r), r.UserAgent(), mfaChallengeTTL)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		h.audit(r, store.RecordAuditParams{
			ActorKind:   store.AuditActorUser,
			ActorUserID: &user.ID,
			Action:      "auth.mfa.challenge",
			TargetType:  "user",
			TargetID:    &user.ID,
		})
		httpx.JSON(w, http.StatusOK, map[string]any{
			"mfa_required":   true,
			"mfa_token":      challengeToken,
			"expires_in_sec": int(mfaChallengeTTL.Seconds()),
			"note":           "POST this token + a TOTP code (or recovery code) to /v1/auth/login/mfa to finish signing in.",
		})
		return
	}

	sess, plain, err := h.store.CreateSession(r.Context(), user.ID, h.sessionTTL,
		clientIP(r), r.UserAgent())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		ActorKind:   store.AuditActorUser,
		ActorUserID: &user.ID,
		Action:      "auth.login.success",
		TargetType:  "session",
		TargetID:    &sess.ID,
	})
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"session_id": sess.ID,
		"token":      plain,
		"expires_at": sess.ExpiresAt,
		"user":       user,
		"note":       "Pass this token in `Authorization: Bearer <token>` on subsequent requests.",
	})
}

// Logout revokes the session that authenticated the current request.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	sid, ok := authctx.SessionIDFrom(r.Context())
	if !ok {
		httpx.Error(w, http.StatusInternalServerError, "session id missing from context")
		return
	}
	if err := h.store.RevokeSession(r.Context(), sid); err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	u, _ := authctx.SessionUserFrom(r.Context())
	h.audit(r, store.RecordAuditParams{
		ActorKind:   store.AuditActorUser,
		ActorUserID: &u.ID,
		Action:      "auth.logout",
		TargetType:  "session",
		TargetID:    &sid,
	})
	w.WriteHeader(http.StatusNoContent)
}

// Me returns the user behind the current session.
func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	u, _ := authctx.SessionUserFrom(r.Context())
	httpx.JSON(w, http.StatusOK, u)
}

// MyOrgs lists every org the session user belongs to (with roles).
func (h *Handlers) MyOrgs(w http.ResponseWriter, r *http.Request) {
	u, _ := authctx.SessionUserFrom(r.Context())
	orgs, err := h.store.ListUserOrgs(r.Context(), u.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, orgs)
}

// allow returns true and lets the caller proceed when the bucket admits this
// key (or when the bucket is nil — limits disabled). On deny it writes a 429
// with a Retry-After header and returns false; the caller should simply
// return. Centralized so every rate-limited endpoint shares the same wire
// shape and header conventions.
func allow(w http.ResponseWriter, b *limiter.Bucket, key string) bool {
	if b == nil {
		return true
	}
	ok, retryAfter := b.Allow(key)
	if ok {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	httpx.Error(w, http.StatusTooManyRequests, "rate limit exceeded; retry shortly")
	return false
}

// audit fills in the request-scoped forensic fields (IP, UA, request ID)
// before delegating to store.RecordAudit. Best-effort — the store layer
// logs failures and never returns them.
func (h *Handlers) audit(r *http.Request, p store.RecordAuditParams) {
	if p.IP == "" {
		p.IP = clientIP(r)
	}
	if p.UserAgent == "" {
		p.UserAgent = r.UserAgent()
	}
	if p.RequestID == "" {
		p.RequestID = logx.RequestID(r.Context())
	}
	h.store.RecordAudit(r.Context(), p)
}

// clientIP picks the leftmost X-Forwarded-For entry, falling back to
// RemoteAddr's host portion. Uses net.SplitHostPort so IPv6 literals
// (`[::1]:8080`) lose their brackets — Postgres `inet` rejects bracketed
// addresses and we store this column unconditionally.
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
