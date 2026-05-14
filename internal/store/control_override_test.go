package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// ─── Control overrides ─────────────────────────────────────────────────

func TestUpsertControlOverride_InsertsThenUpdates(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "OverrideCo", uniqueSlug("ovr"))

	first, err := s.UpsertControlOverride(ctx, org.ID, "SOC2-CC8.1",
		[]byte(`{"min_reviewers": 2}`))
	require.NoError(t, err)
	assert.Equal(t, "SOC2-CC8.1", first.ControlID)

	// Second upsert replaces (same control id) and bumps updated_at.
	time.Sleep(5 * time.Millisecond)
	second, err := s.UpsertControlOverride(ctx, org.ID, "SOC2-CC8.1",
		[]byte(`{"min_reviewers": 4, "block_force_pushes": true}`))
	require.NoError(t, err)
	assert.Equal(t, first.ID, second.ID, "upsert must reuse the existing row")
	assert.True(t, second.UpdatedAt.After(first.UpdatedAt))
	assert.JSONEq(t, `{"min_reviewers": 4, "block_force_pushes": true}`, string(second.Params))
}

func TestUpsertControlOverride_RejectsEmptyParams(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Empty", uniqueSlug("empty"))
	_, err := s.UpsertControlOverride(ctx, org.ID, "X", nil)
	assert.Error(t, err)
}

func TestGetControlOverride_NotFoundIsSentinel(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Miss", uniqueSlug("miss"))
	_, err := s.GetControlOverride(ctx, org.ID, "nope")
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestControlParamsForOrg_DecodesToRunnerShape(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Decode", uniqueSlug("decode"))
	_, err := s.UpsertControlOverride(ctx, org.ID, "SOC2-CC8.1",
		[]byte(`{"min_reviewers": 3}`))
	require.NoError(t, err)
	_, err = s.UpsertControlOverride(ctx, org.ID, "SOC2-CC7.1",
		[]byte(`{"max_high": 5}`))
	require.NoError(t, err)

	params, err := s.ControlParamsForOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, params, 2)
	assert.EqualValues(t, 3, params["SOC2-CC8.1"]["min_reviewers"])
	assert.EqualValues(t, 5, params["SOC2-CC7.1"]["max_high"])
}

func TestDeleteControlOverride_RemovesRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Del", uniqueSlug("del"))
	_, _ = s.UpsertControlOverride(ctx, org.ID, "X", []byte(`{"k":"v"}`))
	require.NoError(t, s.DeleteControlOverride(ctx, org.ID, "X"))
	assert.ErrorIs(t, s.DeleteControlOverride(ctx, org.ID, "X"), store.ErrNotFound)
}

func TestControlOverride_CannotCrossOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))
	_, _ = s.UpsertControlOverride(ctx, a.ID, "SOC2-CC8.1", []byte(`{"min_reviewers": 9}`))

	// Org B looking up org A's override sees ErrNotFound.
	_, err := s.GetControlOverride(ctx, b.ID, "SOC2-CC8.1")
	assert.ErrorIs(t, err, store.ErrNotFound)
}
