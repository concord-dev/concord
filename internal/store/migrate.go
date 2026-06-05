package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

var ErrNoDownMigration = errors.New("store: no down migration for version")

type migration struct {
	version int
	name    string  // canonical name from the up file (e.g. "0001_init")
	up      string  // *.up.sql body — always non-empty on a valid migration
	down    string  // *.down.sql body — empty when no down file exists
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("reading embedded migrations: %w", err)
	}
	byVersion := map[int]*migration{}
	upSeen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		isUp := strings.HasSuffix(name, ".up.sql")
		isDown := strings.HasSuffix(name, ".down.sql")
		if !isUp && !isDown {
			continue
		}
		idx := strings.Index(name, "_")
		if idx <= 0 {
			return nil, fmt.Errorf("migration %q has no version prefix", name)
		}
		v, err := strconv.Atoi(name[:idx])
		if err != nil {
			return nil, fmt.Errorf("migration %q has non-numeric version: %w", name, err)
		}
		body, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}
		m, ok := byVersion[v]
		if !ok {
			m = &migration{version: v}
			byVersion[v] = m
		}
		switch {
		case isUp:
			if existing, dup := upSeen[v]; dup {
				return nil, fmt.Errorf("duplicate migration version %d (%s and %s)", v, existing, name)
			}
			upSeen[v] = name
			m.up = string(body)
			m.name = strings.TrimSuffix(name, ".up.sql")
		case isDown:
			m.down = string(body)
		}
	}
	out := make([]migration, 0, len(byVersion))
	for v, m := range byVersion {
		if m.up == "" {
			return nil, fmt.Errorf("migration version %d has a down file but no up file", v)
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

func (s *Store) Migrate(ctx context.Context) error {
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
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("beginning tx for migration %d: %w", m.version, err)
		}
		if _, err := tx.Exec(ctx, m.up); err != nil {
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

func (s *Store) MigrateDown(ctx context.Context, steps int) error {
	if steps <= 0 {
		return fmt.Errorf("MigrateDown: steps must be >= 1 (got %d) — use MigrateDownAll if you really want to drop every applied migration", steps)
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	byVersion := make(map[int]migration, len(migrations))
	for _, m := range migrations {
		byVersion[m.version] = m
	}

	rows, err := s.pool.Query(ctx,
		`SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT $1`, steps)
	if err != nil {
		return fmt.Errorf("listing applied migrations: %w", err)
	}
	type applied struct {
		version int
		name    string
	}
	var target []applied
	for rows.Next() {
		var a applied
		if err := rows.Scan(&a.version, &a.name); err != nil {
			rows.Close()
			return fmt.Errorf("scanning applied migrations: %w", err)
		}
		target = append(target, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, a := range target {
		m, ok := byVersion[a.version]
		if !ok {
			return fmt.Errorf("schema_migrations references version %d but no embedded migration file matches — manually edit the schema or restore the file", a.version)
		}
		if strings.TrimSpace(m.down) == "" {
			return fmt.Errorf("%w %d (%s)", ErrNoDownMigration, m.version, m.name)
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("beginning tx for down migration %d: %w", m.version, err)
		}
		if _, err := tx.Exec(ctx, m.down); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("applying down migration %d (%s): %w", m.version, m.name, err)
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM schema_migrations WHERE version = $1`, m.version,
		); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("removing schema_migrations row for %d: %w", m.version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing down migration %d: %w", m.version, err)
		}
	}
	return nil
}

func (s *Store) AppliedMigrationVersions(ctx context.Context) ([]int, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT version FROM schema_migrations ORDER BY version ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
