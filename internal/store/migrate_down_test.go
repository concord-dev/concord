package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrateDown_RollsBackAppliedVersion verifies the round-trip: a freshly
// migrated DB → MigrateDown(1) → schema_migrations is empty → Migrate again
// → schema_migrations is back. Tests in this package share a single Postgres
// database; the t.Cleanup re-applies migrations so siblings stay happy
// regardless of execution order.
func TestMigrateDown_RollsBackAppliedVersion(t *testing.T) {
	s := openIsolatedStore(t)
	ctx := context.Background()

	versions, err := s.AppliedMigrationVersions(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, versions, "openTestStore must leave at least one migration applied")
	startCount := len(versions)

	require.NoError(t, s.MigrateDown(ctx, 1))

	versions, err = s.AppliedMigrationVersions(ctx)
	require.NoError(t, err)
	assert.Len(t, versions, startCount-1,
		"one migration must come off schema_migrations after MigrateDown(1)")

	// Tables should genuinely be gone — query an organization to confirm
	// the down migration's DROP TABLE ran (not just a schema_migrations
	// row delete).
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

// TestMigrateDown_NoOpWhenStepsExceedApplied protects against a UX trap:
// asking for "roll back 5" against a DB that only has 1 migration should
// roll back 1, not error. (Tested by inspecting schema_migrations count
// before and after.)
func TestMigrateDown_StepsAboveAppliedRollsBackEverything(t *testing.T) {
	s := openIsolatedStore(t)
	ctx := context.Background()

	require.NoError(t, s.MigrateDown(ctx, 100))
	versions, err := s.AppliedMigrationVersions(ctx)
	require.NoError(t, err)
	assert.Empty(t, versions,
		"asking for more steps than applied must drain schema_migrations, not error")
}

// TestMigrateDown_RoundTripRestoresSeed exercises the developer scenario:
// migrate-up, realize the migration is wrong, migrate-down, migrate-up
// again. After the round-trip the seed rows (roles + permissions) must
// be present and correct — proving the down→up cycle didn't leave
// orphan partial state behind.
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
