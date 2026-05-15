// Package middleware holds the request-scoped auth gates used by the router.
//
// RequireOperator gates /operator/v1/* on a constant-time match against the
// SaaS-operator token (the back-door used to provision tenants — distinct
// from the per-org `admin` RBAC role). RequireSession resolves session tokens
// and injects the user into the request context. RequireOrgPerm resolves
// either a session or an API token for the org named by the {slug} path
// variable and verifies the caller holds the named permission.
package middleware

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// Middleware bundles the auth gates around a Store and the operator token.
type Middleware struct {
	Store         *store.Store
	OperatorToken string
}

// New constructs Middleware with the given dependencies.
func New(s *store.Store, operatorToken string) *Middleware {
	return &Middleware{Store: s, OperatorToken: operatorToken}
}

// RequireOperator returns 503 when OperatorToken is empty (operator endpoints
// disabled). Otherwise it requires a Bearer token that constant-time matches
// OperatorToken. This is the SaaS-operator back-door, not the per-org `admin`
// RBAC role.
func (m *Middleware) RequireOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.OperatorToken == "" {
			httpx.Error(w, http.StatusServiceUnavailable,
				"operator endpoints disabled (set CONCORD_OPERATOR_TOKEN)")
			return
		}
		tok, ok := BearerToken(r)
		if !ok {
			httpx.Error(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(m.OperatorToken)) != 1 {
			httpx.Error(w, http.StatusUnauthorized, "invalid operator token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSession resolves a session token and injects the user into context.
func (m *Middleware) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := BearerToken(r)
		if !ok {
			httpx.Error(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		if !strings.HasPrefix(tok, "concord_sess_") {
			httpx.Error(w, http.StatusUnauthorized, "expected a session token")
			return
		}
		sess, err := m.Store.ResolveSession(r.Context(), tok)
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusUnauthorized, "invalid or expired session")
			return
		}
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		u, err := m.Store.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		ctx := authctx.WithSessionUser(r.Context(), u)
		ctx = authctx.WithSessionID(ctx, sess.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireOrgPerm requires either an API token or a session token authenticated
// for the org named by the {slug} path variable, AND that the caller holds
// the named permission. API tokens implicitly carry every permission of their
// org; users must have a role that grants `perm`.
func (m *Middleware) RequireOrgPerm(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slug := r.PathValue("slug")
			org, err := m.Store.GetOrganizationBySlug(r.Context(), slug)
			if errors.Is(err, store.ErrNotFound) {
				httpx.Error(w, http.StatusNotFound, "no organization with slug "+slug)
				return
			}
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, err.Error())
				return
			}
			tok, ok := BearerToken(r)
			if !ok {
				httpx.Error(w, http.StatusUnauthorized, "missing Authorization header")
				return
			}
			p, ok := m.resolveOrgPrincipal(w, r, org, tok, perm)
			if !ok {
				return
			}
			next.ServeHTTP(w, r.WithContext(authctx.WithPrincipal(r.Context(), p)))
		})
	}
}

func (m *Middleware) resolveOrgPrincipal(w http.ResponseWriter, r *http.Request, org store.Organization, tok, perm string) (authctx.Principal, bool) {
	p := authctx.Principal{Org: org}

	if strings.HasPrefix(tok, "concord_sess_") {
		sess, err := m.Store.ResolveSession(r.Context(), tok)
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusUnauthorized, "invalid or expired session")
			return p, false
		}
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return p, false
		}
		has, err := m.Store.HasPermission(r.Context(), sess.UserID, org.ID, perm)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return p, false
		}
		if !has {
			httpx.Error(w, http.StatusForbidden,
				fmt.Sprintf("missing permission %q on org %q", perm, org.Slug))
			return p, false
		}
		p.UserID = &sess.UserID
		return p, true
	}

	at, err := m.Store.ResolveAPIToken(r.Context(), tok)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusUnauthorized, "invalid token")
		return p, false
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return p, false
	}
	if at.OrgID != org.ID {
		httpx.Error(w, http.StatusForbidden, "token is not scoped to this org")
		return p, false
	}
	p.TokenID = &at.ID
	return p, true
}

// BearerToken extracts the token from Authorization: Bearer <x>. Comparison is
// case-insensitive to match RFC 6750.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	return tok, tok != ""
}
