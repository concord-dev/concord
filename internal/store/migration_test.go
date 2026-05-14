package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Migrations + seed ─────────────────────────────────────────────────

func TestMigrate_IsIdempotent(t *testing.T) {
	s := openTestStore(t)
	require.NoError(t, s.Migrate(context.Background()))
}

func TestSeed_FourRolesAndSixteenPermissions(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	roles, err := s.ListRoles(ctx)
	require.NoError(t, err)
	assert.Len(t, roles, 4)
	perms, err := s.ListPermissions(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(perms), 16, "starter permission set must include >=16")
}

func TestSeed_OwnerHasEveryPermission(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	owner, err := s.GetRoleByName(ctx, "owner")
	require.NoError(t, err)
	allPerms, err := s.ListPermissions(ctx)
	require.NoError(t, err)
	ownerPerms, err := s.ListRolePermissions(ctx, owner.ID)
	require.NoError(t, err)
	assert.Equal(t, len(allPerms), len(ownerPerms),
		"owner role must be bound to every defined permission")
}

func TestSeed_AdminLacksOrgDeleteAndBilling(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	admin, err := s.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	perms, err := s.ListRolePermissions(ctx, admin.ID)
	require.NoError(t, err)
	names := map[string]bool{}
	for _, p := range perms {
		names[p.Name] = true
	}
	assert.False(t, names["org:delete"], "admin must not hold org:delete")
	assert.False(t, names["billing:manage"], "admin must not hold billing:manage")
	assert.True(t, names["runs:create"], "admin should hold runs:create")
}
