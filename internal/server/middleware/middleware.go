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

type Middleware struct {
	Store         *store.Store
	OperatorToken string
}

func New(s *store.Store, operatorToken string) *Middleware {
	return &Middleware{Store: s, OperatorToken: operatorToken}
}

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

func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	return tok, tok != ""
}
