package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// migrationFiles embeds every *.up.sql under internal/store/migrations/. The
// filenames are expected to be `<N>_<description>.up.sql` with N a strictly
// increasing integer that begins at 1.
//
//go:embed migrations/*.up.sql
var migrationFiles embed.FS

// migration is one parsed migration: version number + SQL body.
type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations walks the embedded migrations dir and returns every file
// sorted by version. Returns an error if any filename is malformed or two
// files share the same version number.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("reading embedded migrations: %w", err)
	}
	out := make([]migration, 0, len(entries))
	seen := make(map[int]string)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		// "<N>_<desc>.up.sql"
		idx := strings.Index(e.Name(), "_")
		if idx <= 0 {
			return nil, fmt.Errorf("migration %q has no version prefix", e.Name())
		}
		v, err := strconv.Atoi(e.Name()[:idx])
		if err != nil {
			return nil, fmt.Errorf("migration %q has non-numeric version: %w", e.Name(), err)
		}
		if existing, ok := seen[v]; ok {
			return nil, fmt.Errorf("duplicate migration version %d (%s and %s)", v, existing, e.Name())
		}
		seen[v] = e.Name()
		body, err := migrationFiles.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// Migrate applies every embedded migration that has not yet been recorded in
// schema_migrations. Safe to call on every server startup.
func (s *Store) Migrate(ctx context.Context) error {
	// schema_migrations is bootstrapped here rather than in 0001_init.up.sql so
	// the migrator owns its own state table. Calling this twice is a no-op.
	if _, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	for _, m := range migrations {
		var applied bool
		err := s.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, m.version,
		).Scan(&applied)
		if err != nil {
			return fmt.Errorf("checking migration %d: %w", m.version, err)
		}
		if applied {
			continue
		}
		// Each migration runs inside a transaction so partial failures don't
		// leave the schema in a half-applied state.
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("beginning tx for migration %d: %w", m.version, err)
		}
		if _, err := tx.Exec(ctx, m.sql); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("applying migration %d (%s): %w", m.version, m.name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations(version, name) VALUES ($1, $2)`,
			m.version, m.name,
		); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("recording migration %d: %w", m.version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing migration %d: %w", m.version, err)
		}
	}
	return nil
}
