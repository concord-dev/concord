package store_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// defaultTestDSN matches docker-compose.yml. Override with
// CONCORD_TEST_DATABASE_URL when running against a different Postgres.
const defaultTestDSN = "postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable"

// openTestStore opens a Store against the configured Postgres or skips the
// test when the DB is unreachable. First call also runs migrations.
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

// openIsolatedStore creates a fresh, uniquely-named Postgres database,
// migrates it up, and returns a Store bound to it. t.Cleanup drops the
// database afterwards.
//
// Destructive tests (MigrateDown, schema-rewind round-trips) must use this
// helper rather than openTestStore: dropping tables on the shared `concord`
// database races with tests in the server package, which is in a sibling
// `go test` process holding live connections against the same schema. A
// dedicated per-test DB removes that whole class of flake.
func openIsolatedStore(t *testing.T) *store.Store {
	t.Helper()
	baseDSN := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if baseDSN == "" {
		baseDSN = defaultTestDSN
	}
	// We need a connection to a "control" database (postgres) so we can
	// CREATE the per-test one. Substitute the path component of the DSN.
	u, err := url.Parse(baseDSN)
	require.NoError(t, err, "parsing CONCORD_TEST_DATABASE_URL")
	u.Path = "/postgres"
	ctlDSN := u.String()

	dbName := "concord_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ctl, err := pgx.Connect(ctx, ctlDSN)
	if err != nil {
		t.Skipf("skipping: Postgres control DB not reachable at %s: %v", ctlDSN, err)
	}
	if _, err := ctl.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %q`, dbName)); err != nil {
		_ = ctl.Close(ctx)
		t.Fatalf("creating isolated test DB %s: %v", dbName, err)
	}
	_ = ctl.Close(ctx)

	u.Path = "/" + dbName
	testDSN := u.String()
	s, err := store.Open(ctx, testDSN, store.PoolOptions{MaxConns: 4, MinConns: 1})
	require.NoError(t, err)
	require.NoError(t, s.Migrate(ctx))

	t.Cleanup(func() {
		s.Close()
		// Drop with a fresh control connection — the pool is already closed.
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		dropCtl, err := pgx.Connect(dropCtx, ctlDSN)
		if err != nil {
			t.Logf("isolated-DB cleanup: could not reconnect to %s: %v", ctlDSN, err)
			return
		}
		defer dropCtl.Close(dropCtx)
		// Kick any stragglers before dropping — pgx pool close may not have
		// fully released yet on slow CI.
		_, _ = dropCtl.Exec(dropCtx,
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
			dbName)
		if _, err := dropCtl.Exec(dropCtx, fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, dbName)); err != nil {
			t.Logf("isolated-DB cleanup: dropping %s: %v", dbName, err)
		}
	})

	return s
}

// uniqueSlug yields a slug guaranteed not to collide across parallel tests.
func uniqueSlug(p string) string { return fmt.Sprintf("%s-%s", p, uuid.NewString()[:8]) }

// uniqueEmail does the same for emails.
func uniqueEmail(p string) string {
	return fmt.Sprintf("%s+%s@example.com", p, uuid.NewString()[:8])
}
