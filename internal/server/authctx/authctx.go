// Package authctx carries the authenticated caller identity through the
// per-request context. Middleware injects values via the With* helpers; handlers
// read them via the matching accessors.
package authctx

import (
	"context"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/store"
)

// Principal is everything we need to know about who's calling. Exactly one of
// TokenID or UserID is non-nil; Org is non-zero for org-scoped requests.
type Principal struct {
	Org     store.Organization
	TokenID *uuid.UUID
	UserID  *uuid.UUID
}

type principalKey struct{}
type sessionKey struct{}
type sessionIDKey struct{}

// WithPrincipal returns ctx with p attached.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal attached by middleware, if any.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// WithSessionUser returns ctx with the authenticated session user attached.
func WithSessionUser(ctx context.Context, u store.User) context.Context {
	return context.WithValue(ctx, sessionKey{}, u)
}

// SessionUserFrom returns the user attached by requireSession middleware.
func SessionUserFrom(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(sessionKey{}).(store.User)
	return u, ok
}

// WithSessionID returns ctx with the resolved session UUID attached.
func WithSessionID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, sessionIDKey{}, id)
}

// SessionIDFrom returns the session UUID attached by requireSession.
func SessionIDFrom(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(sessionIDKey{}).(uuid.UUID)
	return id, ok
}
