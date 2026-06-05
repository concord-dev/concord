package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)


func TestCreateUser_WithPassword(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	email := uniqueEmail("alice")
	u, err := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "Alice", LastName: "A", Email: email, Password: "hunter2",
	})
	require.NoError(t, err)
	assert.Equal(t, email, u.Email)

	got, err := s.VerifyUserPassword(ctx, email, "hunter2")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	_, err = s.VerifyUserPassword(ctx, email, "nope")
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestCreateUser_WithoutPassword_CannotLogin(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	email := uniqueEmail("invite")
	_, err := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "Bob", LastName: "B", Email: email,
	})
	require.NoError(t, err)
	_, err = s.VerifyUserPassword(ctx, email, "anything")
	assert.ErrorIs(t, err, store.ErrNotFound,
		"users without a password_hash cannot complete VerifyUserPassword")
}

func TestGetUserByEmail_IsCaseInsensitive(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	email := uniqueEmail("Carol")
	_, _ = s.CreateUser(ctx, store.CreateUserParams{FirstName: "C", LastName: "C", Email: email})
	got, err := s.GetUserByEmail(ctx, strings.ToUpper(email))
	require.NoError(t, err)
	assert.Equal(t, email, got.Email)
}

func TestCreateUser_DuplicateEmailRejected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	email := uniqueEmail("dup")
	_, _ = s.CreateUser(ctx, store.CreateUserParams{FirstName: "A", LastName: "A", Email: email})
	_, err := s.CreateUser(ctx, store.CreateUserParams{FirstName: "B", LastName: "B", Email: strings.ToUpper(email)})
	require.Error(t, err, "case-only-different email must collide")
}
