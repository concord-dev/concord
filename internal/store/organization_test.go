package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// ─── Organizations ─────────────────────────────────────────────────────

func TestCreateOrganization_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	slug := uniqueSlug("acme")
	org, err := s.CreateOrganization(ctx, "Acme", slug)
	require.NoError(t, err)
	got, err := s.GetOrganizationBySlug(ctx, slug)
	require.NoError(t, err)
	assert.Equal(t, org.ID, got.ID)
	assert.WithinDuration(t, time.Now(), got.UpdatedAt, 10*time.Second)
}

func TestCreateOrganization_DuplicateSlugFails(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	slug := uniqueSlug("dup")
	_, _ = s.CreateOrganization(ctx, "A", slug)
	_, err := s.CreateOrganization(ctx, "B", slug)
	require.Error(t, err)
}

func TestGetOrganizationBySlug_NotFoundReturnsSentinel(t *testing.T) {
	s := openTestStore(t)
	_, err := s.GetOrganizationBySlug(context.Background(), "nope-"+uuid.NewString())
	assert.ErrorIs(t, err, store.ErrNotFound)
}
