package store_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
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

// uniqueSlug yields a slug guaranteed not to collide across parallel tests.
func uniqueSlug(p string) string { return fmt.Sprintf("%s-%s", p, uuid.NewString()[:8]) }

// uniqueEmail does the same for emails.
func uniqueEmail(p string) string {
	return fmt.Sprintf("%s+%s@example.com", p, uuid.NewString()[:8])
}
