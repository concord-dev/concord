package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)


func TestAssignRole_IsIdempotent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Idem", uniqueSlug("idem"))
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U", Email: uniqueEmail("u")})
	admin, _ := s.GetRoleByName(ctx, "admin")
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, admin.ID))
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, admin.ID))

	members, err := s.ListOrgMembers(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Len(t, members[0].Roles, 1, "assigning the same role twice must not duplicate")
}

func TestAssignRole_MultipleRolesPerUserOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Multi", uniqueSlug("multi"))
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U", Email: uniqueEmail("u")})
	admin, _ := s.GetRoleByName(ctx, "admin")
	viewer, _ := s.GetRoleByName(ctx, "viewer")
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, admin.ID))
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, viewer.ID))

	members, _ := s.ListOrgMembers(ctx, org.ID)
	require.Len(t, members, 1)
	require.Len(t, members[0].Roles, 2)
}

func TestHasPermission_GrantedViaRole(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Perm", uniqueSlug("perm"))
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U", Email: uniqueEmail("u")})
	viewer, _ := s.GetRoleByName(ctx, "viewer")
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, viewer.ID))

	yes, err := s.HasPermission(ctx, u.ID, org.ID, "runs:read")
	require.NoError(t, err)
	assert.True(t, yes, "viewer holds runs:read")

	no, err := s.HasPermission(ctx, u.ID, org.ID, "runs:create")
	require.NoError(t, err)
	assert.False(t, no, "viewer must NOT hold runs:create")
}

func TestHasPermission_AnyRoleSatisfies(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Any", uniqueSlug("any"))
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U", Email: uniqueEmail("u")})
	viewer, _ := s.GetRoleByName(ctx, "viewer")
	admin, _ := s.GetRoleByName(ctx, "admin")
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, viewer.ID))
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, admin.ID))

	yes, err := s.HasPermission(ctx, u.ID, org.ID, "tokens:create")
	require.NoError(t, err)
	assert.True(t, yes, "admin grants tokens:create even though viewer doesn't")
}

func TestHasPermission_FalseForNonMember(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Strange", uniqueSlug("strange"))
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U", Email: uniqueEmail("u")})
	got, err := s.HasPermission(ctx, u.ID, org.ID, "runs:read")
	require.NoError(t, err)
	assert.False(t, got, "non-members hold no permissions")
}

func TestUserPermissions_DeduplicatesAcrossRoles(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Dedup", uniqueSlug("dedup"))
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U", Email: uniqueEmail("u")})
	admin, _ := s.GetRoleByName(ctx, "admin")
	viewer, _ := s.GetRoleByName(ctx, "viewer")
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, admin.ID))
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, viewer.ID))

	perms, err := s.UserPermissions(ctx, u.ID, org.ID)
	require.NoError(t, err)
	seen := map[string]int{}
	for _, p := range perms {
		seen[p]++
	}
	for p, n := range seen {
		assert.Equal(t, 1, n, "permission %s appeared %d times", p, n)
	}
	assert.Contains(t, perms, "runs:read")
	assert.Contains(t, perms, "tokens:create")
}

func TestRemoveUserFromOrg_DropsEveryRole(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Rm", uniqueSlug("rm"))
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U", Email: uniqueEmail("u")})
	admin, _ := s.GetRoleByName(ctx, "admin")
	viewer, _ := s.GetRoleByName(ctx, "viewer")
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, admin.ID))
	require.NoError(t, s.AssignRole(ctx, u.ID, org.ID, viewer.ID))

	require.NoError(t, s.RemoveUserFromOrg(ctx, u.ID, org.ID))
	members, _ := s.ListOrgMembers(ctx, org.ID)
	assert.Empty(t, members)
	assert.ErrorIs(t, s.RemoveUserFromOrg(ctx, u.ID, org.ID), store.ErrNotFound)
}
