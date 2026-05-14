package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// ─── User sessions ─────────────────────────────────────────────────────

func TestCreateSession_AndResolve(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U",
		Email: uniqueEmail("sess"), Password: "hunter2"})

	sess, plain, err := s.CreateSession(ctx, u.ID, time.Hour, "127.0.0.1", "go-test")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(plain, "concord_sess_"))

	got, err := s.ResolveSession(ctx, plain)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
}

func TestResolveSession_ExpiredRejected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U",
		Email: uniqueEmail("exp"), Password: "hunter2"})
	_, plain, _ := s.CreateSession(ctx, u.ID, -1*time.Second, "", "")
	_, err := s.ResolveSession(ctx, plain)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestRevokeSession_BlocksReuse(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U",
		Email: uniqueEmail("rev"), Password: "hunter2"})
	sess, plain, _ := s.CreateSession(ctx, u.ID, time.Hour, "", "")
	require.NoError(t, s.RevokeSession(ctx, sess.ID))
	_, err := s.ResolveSession(ctx, plain)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestRevokeAllSessionsForUser(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U",
		Email: uniqueEmail("revall"), Password: "hunter2"})
	_, p1, _ := s.CreateSession(ctx, u.ID, time.Hour, "", "")
	_, p2, _ := s.CreateSession(ctx, u.ID, time.Hour, "", "")
	require.NoError(t, s.RevokeAllSessionsForUser(ctx, u.ID))
	_, err1 := s.ResolveSession(ctx, p1)
	_, err2 := s.ResolveSession(ctx, p2)
	assert.ErrorIs(t, err1, store.ErrNotFound)
	assert.ErrorIs(t, err2, store.ErrNotFound)
}
