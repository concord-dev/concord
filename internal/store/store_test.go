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

// defaultTestDSN matches docker-compose.yml. Override via CONCORD_TEST_DATABASE_URL.
const defaultTestDSN = "postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable"

// openTestStore opens a Store against the configured Postgres or skips. The
// first call also runs migrations so subsequent tests can assume the schema
// is current.
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

func uniqueSlug(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, uuid.NewString()[:8])
}

func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s+%s@example.com", prefix, uuid.NewString()[:8])
}

// --- Migrations ---

func TestMigrate_IsIdempotent(t *testing.T) {
	s := openTestStore(t)
	// First Migrate already ran in openTestStore. A second pass must be a no-op.
	require.NoError(t, s.Migrate(context.Background()))
}

// --- Organizations ---

func TestCreateOrganization_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	slug := uniqueSlug("acme")
	org, err := s.CreateOrganization(ctx, "Acme Corp", slug)
	require.NoError(t, err)
	assert.Equal(t, "Acme Corp", org.Name)
	assert.NotZero(t, org.ID)
	assert.WithinDuration(t, time.Now(), org.CreatedAt, 10*time.Second)

	got, err := s.GetOrganizationBySlug(ctx, slug)
	require.NoError(t, err)
	assert.Equal(t, org.ID, got.ID)

	gotByID, err := s.GetOrganizationByID(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, slug, gotByID.Slug)
}

func TestCreateOrganization_DuplicateSlugFails(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	slug := uniqueSlug("dup")
	_, err := s.CreateOrganization(ctx, "First", slug)
	require.NoError(t, err)
	_, err = s.CreateOrganization(ctx, "Second", slug)
	require.Error(t, err, "slug must be unique")
}

func TestGetOrganizationBySlug_NotFoundReturnsSentinel(t *testing.T) {
	s := openTestStore(t)
	_, err := s.GetOrganizationBySlug(context.Background(), "nope-"+uuid.NewString())
	assert.ErrorIs(t, err, store.ErrNotFound)
}

// --- Users ---

func TestCreateUser_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	email := uniqueEmail("alice")

	u, err := s.CreateUser(ctx, email, "Alice")
	require.NoError(t, err)
	assert.Equal(t, "Alice", u.Name)

	got, err := s.GetUserByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, email, got.Email)
}

func TestGetUserByEmail_IsCaseInsensitive(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	email := uniqueEmail("Bob")
	_, err := s.CreateUser(ctx, email, "Bob")
	require.NoError(t, err)

	got, err := s.GetUserByEmail(ctx, strings.ToUpper(email))
	require.NoError(t, err)
	assert.Equal(t, email, got.Email)
}

func TestCreateUser_DuplicateEmailFails(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	email := uniqueEmail("dup")
	_, err := s.CreateUser(ctx, email, "A")
	require.NoError(t, err)
	_, err = s.CreateUser(ctx, email, "B")
	require.Error(t, err, "email must be unique")
}

func TestCreateUser_DuplicateEmailCaseInsensitive(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	email := uniqueEmail("Carol")
	_, err := s.CreateUser(ctx, email, "Carol")
	require.NoError(t, err)
	_, err = s.CreateUser(ctx, strings.ToUpper(email), "Carol2")
	require.Error(t, err, "case-only-different email must collide")
}

// --- Memberships + roles ---

func TestRole_Permits_Hierarchy(t *testing.T) {
	assert.True(t, store.RoleOwner.Permits(store.RoleAdmin))
	assert.True(t, store.RoleAdmin.Permits(store.RoleMember))
	assert.True(t, store.RoleMember.Permits(store.RoleViewer))
	assert.False(t, store.RoleViewer.Permits(store.RoleMember))
	assert.False(t, store.RoleMember.Permits(store.RoleAdmin))
}

func TestAddMember_AndListByOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Mem", uniqueSlug("mem"))
	u1, _ := s.CreateUser(ctx, uniqueEmail("u1"), "U1")
	u2, _ := s.CreateUser(ctx, uniqueEmail("u2"), "U2")

	_, err := s.AddMember(ctx, u1.ID, org.ID, store.RoleOwner)
	require.NoError(t, err)
	_, err = s.AddMember(ctx, u2.ID, org.ID, store.RoleMember)
	require.NoError(t, err)

	members, err := s.ListOrgMembers(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, members, 2)
	// Owner sorts first per the SQL CASE ordering.
	assert.Equal(t, store.RoleOwner, members[0].Role)
	assert.Equal(t, store.RoleMember, members[1].Role)
}

func TestAddMember_UpsertChangesRole(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Upsert", uniqueSlug("upsert"))
	u, _ := s.CreateUser(ctx, uniqueEmail("up"), "U")

	_, err := s.AddMember(ctx, u.ID, org.ID, store.RoleMember)
	require.NoError(t, err)
	m, err := s.AddMember(ctx, u.ID, org.ID, store.RoleAdmin)
	require.NoError(t, err)
	assert.Equal(t, store.RoleAdmin, m.Role, "second call must upgrade the role")

	got, err := s.GetMembership(ctx, u.ID, org.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RoleAdmin, got.Role)
}

func TestAddMember_InvalidRoleIsRejected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Bad", uniqueSlug("bad"))
	u, _ := s.CreateUser(ctx, uniqueEmail("bad"), "Bad")
	_, err := s.AddMember(ctx, u.ID, org.ID, store.Role("superuser"))
	require.Error(t, err)
}

func TestRemoveMember_DeletesRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Del", uniqueSlug("del"))
	u, _ := s.CreateUser(ctx, uniqueEmail("del"), "U")
	_, _ = s.AddMember(ctx, u.ID, org.ID, store.RoleMember)

	require.NoError(t, s.RemoveMember(ctx, u.ID, org.ID))
	_, err := s.GetMembership(ctx, u.ID, org.ID)
	assert.ErrorIs(t, err, store.ErrNotFound)

	// Removing twice surfaces ErrNotFound.
	assert.ErrorIs(t, s.RemoveMember(ctx, u.ID, org.ID), store.ErrNotFound)
}

func TestListUserOrgs(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, uniqueEmail("multi"), "M")
	org1, _ := s.CreateOrganization(ctx, "O1", uniqueSlug("o1"))
	org2, _ := s.CreateOrganization(ctx, "O2", uniqueSlug("o2"))
	_, _ = s.AddMember(ctx, u.ID, org1.ID, store.RoleOwner)
	_, _ = s.AddMember(ctx, u.ID, org2.ID, store.RoleAdmin)

	got, err := s.ListUserOrgs(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, got, 2)
}

// --- API tokens ---

func TestCreateToken_PlaintextIsPrefixedAndUnique(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "TokTest", uniqueSlug("toktest"))

	t1, p1, err := s.CreateToken(ctx, org.ID, "ci", nil)
	require.NoError(t, err)
	t2, p2, err := s.CreateToken(ctx, org.ID, "prod", nil)
	require.NoError(t, err)

	assert.NotEqual(t, p1, p2, "tokens must be unique")
	assert.True(t, strings.HasPrefix(p1, "concord_"))
	assert.Greater(t, len(p1), 30)
	assert.NotEqual(t, t1.ID, t2.ID)
}

func TestCreateToken_AttributedToUser(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Attr", uniqueSlug("attr"))
	u, _ := s.CreateUser(ctx, uniqueEmail("creator"), "C")

	t1, _, err := s.CreateToken(ctx, org.ID, "ci", &u.ID)
	require.NoError(t, err)
	require.NotNil(t, t1.CreatedBy)
	assert.Equal(t, u.ID, *t1.CreatedBy)
}

func TestResolveToken_UpdatesLastUsedAt(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Resolve", uniqueSlug("resolve"))
	_, plain, err := s.CreateToken(ctx, org.ID, "ci", nil)
	require.NoError(t, err)

	got, err := s.ResolveToken(ctx, plain)
	require.NoError(t, err)
	assert.Equal(t, org.ID, got.OrgID)
	require.NotNil(t, got.LastUsedAt)
	assert.WithinDuration(t, time.Now(), *got.LastUsedAt, 5*time.Second)
}

func TestResolveToken_UnknownReturnsSentinel(t *testing.T) {
	s := openTestStore(t)
	_, err := s.ResolveToken(context.Background(), "concord_bogus")
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestDeleteToken_CannotCrossOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))
	tok, _, _ := s.CreateToken(ctx, a.ID, "a-tok", nil)

	assert.ErrorIs(t, s.DeleteToken(ctx, b.ID, tok.ID), store.ErrNotFound)
}

// --- Runs ---

func TestRunLifecycle_PendingRunningSucceeded(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Run", uniqueSlug("run"))
	tok, _, _ := s.CreateToken(ctx, org.ID, "ci", nil)

	r, err := s.CreateRun(ctx, org.ID, &tok.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunPending, r.Status)
	require.NotNil(t, r.TriggeredByToken)
	assert.Equal(t, tok.ID, *r.TriggeredByToken)

	require.NoError(t, s.MarkRunRunning(ctx, r.ID))
	got, err := s.GetRun(ctx, org.ID, r.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunRunning, got.Status)

	require.NoError(t, s.CompleteRun(ctx, r.ID,
		[]byte(`{"pass":3}`), []byte(`[{"id":"X"}]`)))
	final, err := s.GetRun(ctx, org.ID, r.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunSucceeded, final.Status)
	require.NotNil(t, final.CompletedAt)
	assert.JSONEq(t, `{"pass":3}`, string(final.Summary))
}

func TestRunLifecycle_FailedStoresErrorMessage(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Fail", uniqueSlug("fail"))
	r, _ := s.CreateRun(ctx, org.ID, nil)
	require.NoError(t, s.FailRun(ctx, r.ID, "collector blew up"))
	got, err := s.GetRun(ctx, org.ID, r.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunFailed, got.Status)
	assert.Equal(t, "collector blew up", got.ErrorMessage)
}

func TestGetRun_CannotCrossOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))
	r, _ := s.CreateRun(ctx, a.ID, nil)
	_, err := s.GetRun(ctx, b.ID, r.ID)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestListRuns_NewestFirst(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "List", uniqueSlug("list"))
	for range 5 {
		_, _ = s.CreateRun(ctx, org.ID, nil)
		time.Sleep(2 * time.Millisecond)
	}
	got, err := s.ListRuns(ctx, org.ID, 3)
	require.NoError(t, err)
	require.Len(t, got, 3)
	for i := 1; i < len(got); i++ {
		assert.True(t, got[i-1].StartedAt.After(got[i].StartedAt) ||
			got[i-1].StartedAt.Equal(got[i].StartedAt))
	}
}

// TestDeleteOrg_CascadesToChildren verifies the ON DELETE CASCADE chain so a
// tenant deletion doesn't leak rows.
func TestDeleteOrg_CascadesToChildren(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Cascade", uniqueSlug("cascade"))
	u, _ := s.CreateUser(ctx, uniqueEmail("c"), "C")
	_, _ = s.AddMember(ctx, u.ID, org.ID, store.RoleOwner)
	tok, _, _ := s.CreateToken(ctx, org.ID, "x", nil)
	run, _ := s.CreateRun(ctx, org.ID, &tok.ID)

	_, err := s.Pool().Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org.ID)
	require.NoError(t, err)

	var n int
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM api_tokens WHERE id = $1`, tok.ID).Scan(&n))
	assert.Equal(t, 0, n)
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM runs WHERE id = $1`, run.ID).Scan(&n))
	assert.Equal(t, 0, n)
	require.NoError(t, s.Pool().QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE org_id = $1`, org.ID).Scan(&n))
	assert.Equal(t, 0, n)

	// The user itself stays — orgs cascade to memberships/tokens/runs, not users.
	_, err = s.GetUserByID(ctx, u.ID)
	require.NoError(t, err)
}
