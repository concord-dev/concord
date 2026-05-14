package store_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

const defaultTestDSN = "postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable"

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = defaultTestDSN
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := store.Open(ctx, dsn, store.PoolOptions{MaxConns: 4, MinConns: 1})
	if err != nil {
		t.Skipf("skipping: Postgres not reachable at %s (run `docker compose up -d postgres`): %v", dsn, err)
	}
	require.NoError(t, s.Migrate(ctx))
	t.Cleanup(s.Close)
	return s
}

func uniqueSlug(p string) string  { return fmt.Sprintf("%s-%s", p, uuid.NewString()[:8]) }
func uniqueEmail(p string) string { return fmt.Sprintf("%s+%s@example.com", p, uuid.NewString()[:8]) }

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

// ─── Users ─────────────────────────────────────────────────────────────

func TestCreateUser_WithPassword(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	email := uniqueEmail("alice")
	u, err := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "Alice", LastName: "A", Email: email, Password: "hunter2",
	})
	require.NoError(t, err)
	assert.Equal(t, email, u.Email)

	// Password verification should succeed.
	got, err := s.VerifyUserPassword(ctx, email, "hunter2")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	// Wrong password is ErrNotFound (no user enumeration).
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

// ─── RBAC (memberships + permissions) ──────────────────────────────────

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

// ─── API tokens ────────────────────────────────────────────────────────

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

	// Revoked tokens disappear from ListAPITokens.
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

// ─── User sessions ─────────────────────────────────────────────────────

func TestCreateSession_AndResolve(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U",
		Email: uniqueEmail("sess"), Password: "hunter2"})

	sess, plain, err := s.CreateSession(ctx, u.ID, time.Hour, "127.0.0.1", "go-test")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(plain, "concord_sess_"))

	got, err := s.ResolveSession(ctx, plain)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
}

func TestResolveSession_ExpiredRejected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U",
		Email: uniqueEmail("exp"), Password: "hunter2"})
	_, plain, _ := s.CreateSession(ctx, u.ID, -1*time.Second, "", "")
	_, err := s.ResolveSession(ctx, plain)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestRevokeSession_BlocksReuse(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U",
		Email: uniqueEmail("rev"), Password: "hunter2"})
	sess, plain, _ := s.CreateSession(ctx, u.ID, time.Hour, "", "")
	require.NoError(t, s.RevokeSession(ctx, sess.ID))
	_, err := s.ResolveSession(ctx, plain)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestRevokeAllSessionsForUser(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{FirstName: "U", LastName: "U",
		Email: uniqueEmail("revall"), Password: "hunter2"})
	_, p1, _ := s.CreateSession(ctx, u.ID, time.Hour, "", "")
	_, p2, _ := s.CreateSession(ctx, u.ID, time.Hour, "", "")
	require.NoError(t, s.RevokeAllSessionsForUser(ctx, u.ID))
	_, err1 := s.ResolveSession(ctx, p1)
	_, err2 := s.ResolveSession(ctx, p2)
	assert.ErrorIs(t, err1, store.ErrNotFound)
	assert.ErrorIs(t, err2, store.ErrNotFound)
}

// ─── Runs ──────────────────────────────────────────────────────────────

func TestRunLifecycle_PendingRunningSucceeded(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Run", uniqueSlug("run"))
	tok, _, _ := s.CreateAPIToken(ctx, org.ID, "ci", nil)

	r, err := s.CreateRun(ctx, store.CreateRunParams{OrgID: org.ID, TokenID: &tok.ID})
	require.NoError(t, err)
	assert.Equal(t, store.RunPending, r.Status)
	require.NoError(t, s.MarkRunRunning(ctx, r.ID))
	require.NoError(t, s.CompleteRun(ctx, r.ID,
		[]byte(`{"pass":3}`), []byte(`[{"id":"X"}]`)))
	final, err := s.GetRun(ctx, org.ID, r.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunSucceeded, final.Status)
	require.NotNil(t, final.TriggeredByToken)
}

func TestGetRun_CannotCrossOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))
	r, _ := s.CreateRun(ctx, store.CreateRunParams{OrgID: a.ID})
	_, err := s.GetRun(ctx, b.ID, r.ID)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

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

// TestDeleteOrg_CascadesEverywhere verifies the ON DELETE CASCADE chain so
// the soft tenant-deletion path doesn't leak rows across the join tables.
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
