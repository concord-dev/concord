package authctx

import (
	"context"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/store"
)

type Principal struct {
	Org     store.Organization
	TokenID *uuid.UUID
	UserID  *uuid.UUID
}

type principalKey struct{}
type sessionKey struct{}
type sessionIDKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

func WithSessionUser(ctx context.Context, u store.User) context.Context {
	return context.WithValue(ctx, sessionKey{}, u)
}

func SessionUserFrom(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(sessionKey{}).(store.User)
	return u, ok
}

func WithSessionID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, sessionIDKey{}, id)
}

func SessionIDFrom(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(sessionIDKey{}).(uuid.UUID)
	return id, ok
}
