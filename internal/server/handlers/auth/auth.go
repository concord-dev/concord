// Package auth hosts the session-lifecycle and session-scoped endpoints:
// /v1/auth/login, /v1/auth/logout, /v1/me, /v1/me/orgs.
package auth

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// Handlers bundles dependencies for the auth route group.
type Handlers struct {
	store      *store.Store
	sessionTTL time.Duration
}

// New constructs Handlers with the given Store and session lifetime.
func New(s *store.Store, sessionTTL time.Duration) *Handlers {
	return &Handlers{store: s, sessionTTL: sessionTTL}
}

// Login exchanges email + password for a session token. Same error message for
// unknown email and bad password to prevent user enumeration.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
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
	user, err := h.store.VerifyUserPassword(r.Context(), body.Email, body.Password)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess, plain, err := h.store.CreateSession(r.Context(), user.ID, h.sessionTTL,
		clientIP(r), r.UserAgent())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
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
