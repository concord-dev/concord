package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

func TestSetUserAuditor_RoundTripsAndIsIdempotent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "A", LastName: "A", Email: uniqueEmail("audit"),
	})
	assert.False(t, u.IsAuditor,
		"new users must default to is_auditor=false — promotion is an explicit operator action")

	require.NoError(t, s.SetUserAuditor(ctx, u.ID, true))
	got, err := s.IsUserAuditor(ctx, u.ID)
	require.NoError(t, err)
	assert.True(t, got)

	require.NoError(t, s.SetUserAuditor(ctx, u.ID, true))

	require.NoError(t, s.SetUserAuditor(ctx, u.ID, false))
	got, err = s.IsUserAuditor(ctx, u.ID)
	require.NoError(t, err)
	assert.False(t, got)
}

func TestSetUserAuditor_UnknownUserReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	err := s.SetUserAuditor(ctx, uuidNil(t), true)
	assert.ErrorIs(t, err, store.ErrNotFound,
		"flipping the flag on a missing user must surface ErrNotFound — the operator handler relies on this branch for 404s")
}

func TestHasPermission_AuditorShortCircuitsReadsAcrossAnyOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	auditor, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "Au", LastName: "ditor", Email: uniqueEmail("auditor"),
	})
	require.NoError(t, s.SetUserAuditor(ctx, auditor.ID, true))

	a, _ := s.CreateOrganization(ctx, "OrgA", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "OrgB", uniqueSlug("b"))

	for _, org := range []store.Organization{a, b} {
		for _, perm := range []string{"runs:read", "controls:read", "audit:read", "webhooks:read"} {
			got, err := s.HasPermission(ctx, auditor.ID, org.ID, perm)
			require.NoError(t, err)
			assert.Truef(t, got,
				"auditor must pass %s on org %s without being a member — that's the whole feature",
				perm, org.Slug)
		}
	}
}

func TestHasPermission_AuditorDoesNotGrantWritePermissions(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	auditor, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "A", LastName: "u", Email: uniqueEmail("auditor"),
	})
	require.NoError(t, s.SetUserAuditor(ctx, auditor.ID, true))
	org, _ := s.CreateOrganization(ctx, "X", uniqueSlug("x"))

	for _, perm := range []string{
		"runs:create", "runs:delete", "controls:override",
		"webhooks:create", "webhooks:delete",
		"members:invite", "members:remove",
		"trust_portal:manage", "org:update", "org:delete",
	} {
		got, err := s.HasPermission(ctx, auditor.ID, org.ID, perm)
		require.NoError(t, err)
		assert.Falsef(t, got,
			"auditor must NOT have write permission %q — that would defeat the read-only intent of the flag",
			perm)
	}
}

func TestHasPermission_NonAuditorStillGatedByPerOrgRole(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "n", LastName: "o", Email: uniqueEmail("nonauditor"),
	})
	org, _ := s.CreateOrganization(ctx, "X", uniqueSlug("x"))

	got, err := s.HasPermission(ctx, u.ID, org.ID, "runs:read")
	require.NoError(t, err)
	assert.False(t, got, "non-member must not have read access — auditor flag is the ONLY cross-org grant")
}

func TestListUserOrgs_AuditorSeesEveryOrgWithSyntheticRole(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))
	c, _ := s.CreateOrganization(ctx, "C", uniqueSlug("c"))

	auditor, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "Au", LastName: "Bm", Email: uniqueEmail("auditor"),
	})
	owner, _ := s.GetRoleByName(ctx, "owner")
	require.NoError(t, s.AssignRole(ctx, auditor.ID, a.ID, owner.ID))
	require.NoError(t, s.SetUserAuditor(ctx, auditor.ID, true))

	got, err := s.ListUserOrgs(ctx, auditor.ID)
	require.NoError(t, err)

	byOrgID := make(map[string]store.UserOrg, len(got))
	for _, uo := range got {
		byOrgID[uo.Organization.ID.String()] = uo
	}

	require.Contains(t, byOrgID, a.ID.String())
	if assert.Len(t, byOrgID[a.ID.String()].Roles, 1) {
		assert.Equal(t, "owner", byOrgID[a.ID.String()].Roles[0].Name,
			"real role bindings must take precedence over the synthetic auditor role on orgs the user actually belongs to")
	}

	for _, org := range []store.Organization{b, c} {
		uo, present := byOrgID[org.ID.String()]
		require.Truef(t, present, "auditor must see org %s in their org list", org.Slug)
		require.Len(t, uo.Roles, 1)
		assert.Equal(t, "auditor", uo.Roles[0].Name,
			"non-member orgs must surface the synthetic auditor role so the UI can distinguish them")
	}
}

func TestListAuditors_FiltersToFlaggedUsers(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	au, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "A", LastName: "u", Email: uniqueEmail("auditor"),
	})
	require.NoError(t, s.SetUserAuditor(ctx, au.ID, true))
	_, _ = s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "R", LastName: "g", Email: uniqueEmail("regular"),
	})

	got, err := s.ListAuditors(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, got)
	for _, u := range got {
		assert.Truef(t, u.IsAuditor, "ListAuditors must only return users with is_auditor=true (got %s)", u.Email)
	}
}

func uuidNil(t *testing.T) (zero [16]byte) {
	t.Helper()
	return zero
}
