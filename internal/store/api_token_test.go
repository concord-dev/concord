package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)


func TestCreateAPIToken_PlaintextPrefixedAndUnique(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Tok", uniqueSlug("tok"))
	_, p1, _ := s.CreateAPIToken(ctx, org.ID, "a", nil)
	_, p2, _ := s.CreateAPIToken(ctx, org.ID, "b", nil)
	assert.NotEqual(t, p1, p2)
	assert.True(t, strings.HasPrefix(p1, "concord_"))
}

func TestResolveAPIToken_BumpsLastUsedAt(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Use", uniqueSlug("use"))
	_, plain, _ := s.CreateAPIToken(ctx, org.ID, "ci", nil)
	got, err := s.ResolveAPIToken(ctx, plain)
	require.NoError(t, err)
	require.NotNil(t, got.LastUsedAt)
}

func TestRevokeAPIToken_BlocksFutureUse(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Rev", uniqueSlug("rev"))
	tok, plain, _ := s.CreateAPIToken(ctx, org.ID, "ci", nil)
	require.NoError(t, s.RevokeAPIToken(ctx, org.ID, tok.ID))

	_, err := s.ResolveAPIToken(ctx, plain)
	assert.ErrorIs(t, err, store.ErrNotFound)

	toks, _ := s.ListAPITokens(ctx, org.ID)
	assert.Empty(t, toks)
}

func TestRevokeAPIToken_CannotCrossOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))
	tok, _, _ := s.CreateAPIToken(ctx, a.ID, "a-tok", nil)
	assert.ErrorIs(t, s.RevokeAPIToken(ctx, b.ID, tok.ID), store.ErrNotFound)
}
