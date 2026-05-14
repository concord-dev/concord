package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/store"
)

// principal is everything we need to know about who's calling. Exactly one
// of TokenID or UserID is non-nil; Org is non-zero for org-scoped requests.
type principal struct {
	Org     store.Organization
	TokenID *uuid.UUID
	UserID  *uuid.UUID
}

type principalCtxKey struct{}
type sessionCtxKey struct{}
type sessionIDCtxKey struct{}

// principalFromContext returns the auth context injected by requireOrgPerm.
func principalFromContext(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(principal)
	return p, ok
}

// sessionUserFromContext returns the user injected by requireSession.
func sessionUserFromContext(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(sessionCtxKey{}).(store.User)
	return u, ok
}

// requireAdmin gates /admin/v1/* on a constant-time match against the
// CONCORD_ADMIN_TOKEN. When the env var is unset the route returns 503.
func (c *Concord) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.AdminToken == "" {
			writeError(w, http.StatusServiceUnavailable,
				"admin endpoints disabled (set CONCORD_ADMIN_TOKEN)")
			return
		}
		tok, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(c.AdminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireSession resolves a session token and injects the user into context.
// Session tokens are distinguished from API tokens by their prefix.
func (c *Concord) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		if !strings.HasPrefix(tok, "concord_sess_") {
			writeError(w, http.StatusUnauthorized, "expected a session token")
			return
		}
		sess, err := c.Store.ResolveSession(r.Context(), tok)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid or expired session")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		u, err := c.Store.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey{}, u)
		ctx = context.WithValue(ctx, sessionIDCtxKey{}, sess.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireOrgPerm requires either an API token or a session token authenticating
// for the org named by the {slug} path variable, AND that the caller hold the
// named permission. API tokens implicitly carry every permission of their org;
// users must have a role that grants `perm` via role_permission.
func (c *Concord) requireOrgPerm(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slug := r.PathValue("slug")
			org, err := c.Store.GetOrganizationBySlug(r.Context(), slug)
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "no organization with slug "+slug)
				return
			}
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			tok, ok := bearerToken(r)
			if !ok {
				writeError(w, http.StatusUnauthorized, "missing Authorization header")
				return
			}
			p, ok := c.resolveOrgPrincipal(w, r, org, tok, perm)
			if !ok {
				return
			}
			ctx := context.WithValue(r.Context(), principalCtxKey{}, p)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolveOrgPrincipal handles the two-branched resolution (session vs API
// token) inside requireOrgPerm. Returns ok=false after the helper has already
// written the error response.
func (c *Concord) resolveOrgPrincipal(w http.ResponseWriter, r *http.Request, org store.Organization, tok, perm string) (principal, bool) {
	p := principal{Org: org}

	if strings.HasPrefix(tok, "concord_sess_") {
		sess, err := c.Store.ResolveSession(r.Context(), tok)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid or expired session")
			return p, false
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return p, false
		}
		has, err := c.Store.HasPermission(r.Context(), sess.UserID, org.ID, perm)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return p, false
		}
		if !has {
			writeError(w, http.StatusForbidden,
				fmt.Sprintf("missing permission %q on org %q", perm, org.Slug))
			return p, false
		}
		p.UserID = &sess.UserID
		return p, true
	}

	at, err := c.Store.ResolveAPIToken(r.Context(), tok)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return p, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return p, false
	}
	if at.OrgID != org.ID {
		writeError(w, http.StatusForbidden, "token is not scoped to this org")
		return p, false
	}
	p.TokenID = &at.ID
	return p, true
}

// bearerToken extracts the token from Authorization: Bearer <x>.
// Comparison is case-insensitive to match RFC 6750.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	return tok, tok != ""
}
