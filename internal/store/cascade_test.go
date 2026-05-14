package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

func TestDeleteOrg_CascadesEverywhere(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Cascade", uniqueSlug("cascade"))
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U", Email: uniqueEmail("cas")})
	admin, _ := s.GetRoleByName(ctx, "admin")
	_ = s.AssignRole(ctx, u.ID, org.ID, admin.ID)
	tok, _, _ := s.CreateAPIToken(ctx, org.ID, "x", nil)
	run, _ := s.CreateRun(ctx, store.CreateRunParams{OrgID: org.ID})

	_, err := s.Pool().Exec(ctx, `DELETE FROM organization WHERE id = $1`, org.ID)
	require.NoError(t, err)

	var n int
	require.NoError(t, s.Pool().QueryRow(ctx, `SELECT count(*) FROM api_token WHERE id = $1`, tok.ID).Scan(&n))
	assert.Equal(t, 0, n)
	require.NoError(t, s.Pool().QueryRow(ctx, `SELECT count(*) FROM run WHERE id = $1`, run.ID).Scan(&n))
	assert.Equal(t, 0, n)
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM user_org_role WHERE org_id = $1`, org.ID).Scan(&n))
	assert.Equal(t, 0, n)
	_, err = s.GetUserByID(ctx, u.ID)
	require.NoError(t, err, "user must survive org deletion")
}
