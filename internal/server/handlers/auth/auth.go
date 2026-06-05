package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/notify/mail"
	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/bg"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/server/limiter"
	"github.com/concord-dev/concord/internal/store"
)

type Limits struct {
	LoginIP     limiter.Bucket // per source IP for POST /v1/auth/login
	LoginEmail  limiter.Bucket // per email for POST /v1/auth/login (anti-stuffing)
	PWResetIP   limiter.Bucket // per source IP for POST /v1/auth/password-reset
	PWConfirmIP limiter.Bucket // per source IP for POST /v1/auth/password-reset/confirm
	MFASubmitIP limiter.Bucket // per source IP for POST /v1/auth/login/mfa
}

const mfaChallengeTTL = 5 * time.Minute

type Handlers struct {
	store      *store.Store
	sessionTTL time.Duration
	limits     Limits
	mailer     mail.Mailer
	bg         *bg.Runner
}

func New(s *store.Store, sessionTTL time.Duration, limits Limits, mailer mail.Mailer, runner *bg.Runner) *Handlers {
	return &Handlers{store: s, sessionTTL: sessionTTL, limits: limits, mailer: mailer, bg: runner}
}

func (h *Handlers) goAsync(fn func()) {
	if h.bg != nil {
		h.bg.Go(fn)
		return
	}
	go fn()
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	if !allow(w, h.limits.LoginIP, httpx.ClientIP(r)) {
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

	enrolled, err := h.store.IsUserMFAEnrolled(r.Context(), user.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if enrolled {
		_, challengeToken, err := h.store.CreateMFAChallenge(
			r.Context(), user.ID, httpx.ClientIP(r), r.UserAgent(), mfaChallengeTTL)
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
		httpx.ClientIP(r), r.UserAgent())
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

func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	u, _ := authctx.SessionUserFrom(r.Context())
	httpx.JSON(w, http.StatusOK, u)
}

func (h *Handlers) MyOrgs(w http.ResponseWriter, r *http.Request) {
	u, _ := authctx.SessionUserFrom(r.Context())
	orgs, err := h.store.ListUserOrgs(r.Context(), u.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, orgs)
}

func allow(w http.ResponseWriter, b limiter.Bucket, key string) bool {
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

func (h *Handlers) audit(r *http.Request, p store.RecordAuditParams) {
	if p.IP == "" {
		p.IP = httpx.ClientIP(r)
	}
	if p.UserAgent == "" {
		p.UserAgent = r.UserAgent()
	}
	if p.RequestID == "" {
		p.RequestID = logx.RequestID(r.Context())
	}
	h.store.RecordAudit(r.Context(), p)
}

