package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// defaultTestDSN matches docker-compose.yml. Override via CONCORD_TEST_DATABASE_URL.
const defaultTestDSN = "postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable"

// openTestStore opens a Store against the configured Postgres or skips the
// test if the database is unreachable. The first call also runs migrations
// so subsequent tests can assume the schema is current.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = defaultTestDSN
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Skipf("skipping: Postgres not reachable at %s (run `docker compose up -d postgres`): %v", dsn, err)
	}
	require.NoError(t, s.Migrate(ctx))
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// uniqueSlug yields a slug guaranteed not to collide across parallel tests.
func uniqueSlug(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, uuid.NewString()[:8])
}

func TestMigrate_IsIdempotent(t *testing.T) {
	s := openTestStore(t)
	// First Migrate already ran in openTestStore. A second pass must be a no-op.
	require.NoError(t, s.Migrate(context.Background()))
}

func TestCreateTenant_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	slug := uniqueSlug("acme")
	tenant, err := s.CreateTenant(ctx, "Acme Corp", slug)
	require.NoError(t, err)
	assert.Equal(t, "Acme Corp", tenant.Name)
	assert.NotZero(t, tenant.ID)
	assert.WithinDuration(t, time.Now(), tenant.CreatedAt, 10*time.Second)

	got, err := s.GetTenantBySlug(ctx, slug)
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, got.ID)

	gotByID, err := s.GetTenantByID(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, slug, gotByID.Slug)
}

func TestCreateTenant_DuplicateSlugFails(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	slug := uniqueSlug("dup")
	_, err := s.CreateTenant(ctx, "First", slug)
	require.NoError(t, err)
	_, err = s.CreateTenant(ctx, "Second", slug)
	require.Error(t, err, "slug must be unique")
}

func TestGetTenantBySlug_NotFoundReturnsSentinel(t *testing.T) {
	s := openTestStore(t)
	_, err := s.GetTenantBySlug(context.Background(), "nope-"+uuid.NewString())
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestCreateToken_PlaintextIsRandomAndPrefixed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant, err := s.CreateTenant(ctx, "TokTest", uniqueSlug("toktest"))
	require.NoError(t, err)

	tok1, plain1, err := s.CreateToken(ctx, tenant.ID, "ci")
	require.NoError(t, err)
	tok2, plain2, err := s.CreateToken(ctx, tenant.ID, "prod")
	require.NoError(t, err)

	assert.NotEqual(t, plain1, plain2, "tokens must be unique")
	assert.True(t, strings.HasPrefix(plain1, "concord_"))
	assert.True(t, strings.HasPrefix(plain2, "concord_"))
	assert.Greater(t, len(plain1), 30, "256 bits in base64 should be >30 chars")
	assert.NotEqual(t, tok1.ID, tok2.ID)
}

func TestResolveToken_UpdatesLastUsedAt(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant, err := s.CreateTenant(ctx, "ResolveTest", uniqueSlug("resolve"))
	require.NoError(t, err)
	_, plain, err := s.CreateToken(ctx, tenant.ID, "ci")
	require.NoError(t, err)

	got, err := s.ResolveToken(ctx, plain)
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, got.TenantID)
	require.NotNil(t, got.LastUsedAt, "ResolveToken must set last_used_at")
	assert.WithinDuration(t, time.Now(), *got.LastUsedAt, 5*time.Second)
}

func TestResolveToken_UnknownTokenReturnsSentinel(t *testing.T) {
	s := openTestStore(t)
	_, err := s.ResolveToken(context.Background(), "concord_bogus")
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestListTokens_NewestFirst(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant, _ := s.CreateTenant(ctx, "ListT", uniqueSlug("listt"))
	_, _, _ = s.CreateToken(ctx, tenant.ID, "first")
	time.Sleep(20 * time.Millisecond)
	_, _, _ = s.CreateToken(ctx, tenant.ID, "second")

	toks, err := s.ListTokens(ctx, tenant.ID)
	require.NoError(t, err)
	require.Len(t, toks, 2)
	assert.Equal(t, "second", toks[0].Name)
	assert.Equal(t, "first", toks[1].Name)
}

func TestDeleteToken_RemovesRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant, _ := s.CreateTenant(ctx, "DelT", uniqueSlug("delt"))
	tok, plain, _ := s.CreateToken(ctx, tenant.ID, "ci")

	require.NoError(t, s.DeleteToken(ctx, tenant.ID, tok.ID))
	_, err := s.ResolveToken(ctx, plain)
	assert.ErrorIs(t, err, store.ErrNotFound)

	// Deleting twice must surface ErrNotFound.
	assert.ErrorIs(t, s.DeleteToken(ctx, tenant.ID, tok.ID), store.ErrNotFound)
}

func TestDeleteToken_CannotCrossTenant(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateTenant(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateTenant(ctx, "B", uniqueSlug("b"))
	tok, _, _ := s.CreateToken(ctx, a.ID, "a-tok")

	// Attempting to delete a-tok as tenant B must return ErrNotFound.
	assert.ErrorIs(t, s.DeleteToken(ctx, b.ID, tok.ID), store.ErrNotFound)
}

func TestRunLifecycle_PendingRunningSucceeded(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant, _ := s.CreateTenant(ctx, "RunT", uniqueSlug("runt"))

	r, err := s.CreateRun(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunPending, r.Status)

	require.NoError(t, s.MarkRunRunning(ctx, r.ID))
	got, err := s.GetRun(ctx, tenant.ID, r.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunRunning, got.Status)
	assert.Nil(t, got.CompletedAt)

	summary := []byte(`{"pass":3,"fail":0}`)
	findings := []byte(`[{"control_id":"X","status":"pass"}]`)
	require.NoError(t, s.CompleteRun(ctx, r.ID, summary, findings))

	final, err := s.GetRun(ctx, tenant.ID, r.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunSucceeded, final.Status)
	require.NotNil(t, final.CompletedAt)
	assert.JSONEq(t, string(summary), string(final.Summary))
	assert.JSONEq(t, string(findings), string(final.Findings))
}

func TestRunLifecycle_FailedStoresErrorMessage(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant, _ := s.CreateTenant(ctx, "FailT", uniqueSlug("failt"))
	r, _ := s.CreateRun(ctx, tenant.ID)

	require.NoError(t, s.FailRun(ctx, r.ID, "collector blew up"))

	got, err := s.GetRun(ctx, tenant.ID, r.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunFailed, got.Status)
	assert.Equal(t, "collector blew up", got.ErrorMessage)
}

func TestGetRun_CannotCrossTenant(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateTenant(ctx, "AT", uniqueSlug("at"))
	b, _ := s.CreateTenant(ctx, "BT", uniqueSlug("bt"))
	r, _ := s.CreateRun(ctx, a.ID)
	_, err := s.GetRun(ctx, b.ID, r.ID)
	assert.ErrorIs(t, err, store.ErrNotFound, "tenant isolation must hold")
}

func TestListRuns_NewestFirstAndRespectsLimit(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant, _ := s.CreateTenant(ctx, "ListR", uniqueSlug("listr"))
	for range 5 {
		_, _ = s.CreateRun(ctx, tenant.ID)
		time.Sleep(2 * time.Millisecond)
	}

	got, err := s.ListRuns(ctx, tenant.ID, 3)
	require.NoError(t, err)
	require.Len(t, got, 3)
	// Newest first.
	for i := 1; i < len(got); i++ {
		assert.True(t, got[i-1].StartedAt.After(got[i].StartedAt) || got[i-1].StartedAt.Equal(got[i].StartedAt))
	}
}

// TestDeleteTenant_CascadesToTokensAndRuns proves the ON DELETE CASCADE
// constraints — a real concern because tenants that hold tokens or runs are
// the common case, and leaking those on tenant removal would be a data leak.
func TestDeleteTenant_CascadesToTokensAndRuns(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	tenant, _ := s.CreateTenant(ctx, "Cascade", uniqueSlug("cascade"))
	tok, _, _ := s.CreateToken(ctx, tenant.ID, "x")
	run, _ := s.CreateRun(ctx, tenant.ID)

	// There's no DeleteTenant API yet — exercise the cascade directly via DB.
	_, err := s.DB().ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenant.ID)
	require.NoError(t, err)

	var n int
	require.NoError(t, s.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM api_tokens WHERE id = $1`, tok.ID).Scan(&n))
	assert.Equal(t, 0, n, "token row should cascade-delete with tenant")

	require.NoError(t, s.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM runs WHERE id = $1`, run.ID).Scan(&n))
	assert.Equal(t, 0, n, "run row should cascade-delete with tenant")
}

// Force sql.ErrNoRows path through GetTenantByID for completeness.
func TestGetTenantByID_NotFoundReturnsSentinel(t *testing.T) {
	s := openTestStore(t)
	_, err := s.GetTenantByID(context.Background(), uuid.New())
	assert.ErrorIs(t, err, store.ErrNotFound)
	// And the wrapped sql.ErrNoRows must not leak through.
	assert.NotErrorIs(t, err, sql.ErrNoRows)
}
