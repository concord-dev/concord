package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/store"
)

// handleLogin exchanges email + password for a session token. Same error
// message for unknown email and bad password to prevent user enumeration.
func (c *Concord) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	user, err := c.Store.VerifyUserPassword(r.Context(), body.Email, body.Password)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess, plain, err := c.Store.CreateSession(r.Context(), user.ID, c.SessionTTL,
		clientIP(r), r.UserAgent())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id": sess.ID,
		"token":      plain,
		"expires_at": sess.ExpiresAt,
		"user":       user,
		"note":       "Pass this token in `Authorization: Bearer <token>` on subsequent requests.",
	})
}

// handleLogout revokes the session that authenticated the current request.
func (c *Concord) handleLogout(w http.ResponseWriter, r *http.Request) {
	sid, ok := r.Context().Value(sessionIDCtxKey{}).(uuid.UUID)
	if !ok {
		writeError(w, http.StatusInternalServerError, "session id missing from context")
		return
	}
	if err := c.Store.RevokeSession(r.Context(), sid); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSessionMe returns the user behind the current session.
func (c *Concord) handleSessionMe(w http.ResponseWriter, r *http.Request) {
	u, _ := sessionUserFromContext(r.Context())
	writeJSON(w, http.StatusOK, u)
}

// handleSessionOrgs lists every org the session user belongs to (with roles).
func (c *Concord) handleSessionOrgs(w http.ResponseWriter, r *http.Request) {
	u, _ := sessionUserFromContext(r.Context())
	orgs, err := c.Store.ListUserOrgs(r.Context(), u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, orgs)
}

// clientIP picks the leftmost X-Forwarded-For entry when behind a proxy,
// falling back to RemoteAddr's host portion.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
