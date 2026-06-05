package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateDown_RollsBackAppliedVersion(t *testing.T) {
	s := openIsolatedStore(t)
	ctx := context.Background()

	versions, err := s.AppliedMigrationVersions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, versions, "openTestStore must leave at least one migration applied")
	startCount := len(versions)

	require.NoError(t, s.MigrateDown(ctx, startCount))

	versions, err = s.AppliedMigrationVersions(ctx)
	require.NoError(t, err)
	assert.Empty(t, versions,
		"schema_migrations must be empty after rolling everything back")

	_, err = s.Pool().Exec(ctx, `SELECT 1 FROM organization LIMIT 1`)
	assert.Error(t, err,
		"organization table must be dropped after MigrateDown — a schema_migrations row delete alone isn't enough")
}

func TestMigrateDown_RejectsNonPositiveSteps(t *testing.T) {
	s := openIsolatedStore(t)
	ctx := context.Background()
	for _, n := range []int{0, -1, -100} {
		err := s.MigrateDown(ctx, n)
		assert.Error(t, err,
			"MigrateDown(%d) must error — silent 'wipe everything' would be a foot-gun", n)
	}
}

func TestMigrateDown_StepsAboveAppliedRollsBackEverything(t *testing.T) {
	s := openIsolatedStore(t)
	ctx := context.Background()

	require.NoError(t, s.MigrateDown(ctx, 100))
	versions, err := s.AppliedMigrationVersions(ctx)
	require.NoError(t, err)
	assert.Empty(t, versions,
		"asking for more steps than applied must drain schema_migrations, not error")
}

func TestMigrateDown_RoundTripRestoresSeed(t *testing.T) {
	s := openIsolatedStore(t)
	ctx := context.Background()
	require.NoError(t, s.MigrateDown(ctx, 1))
	require.NoError(t, s.Migrate(ctx))

	roles, err := s.ListRoles(ctx)
	require.NoError(t, err)
	assert.Len(t, roles, 4,
		"seed roles must be back after down→up — the canonical 'I broke my migration, let me retry' loop must converge")
}
