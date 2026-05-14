// Package store is the Postgres-backed persistence layer for concord-server.
// It owns the database schema, exposes typed CRUD over tenants, API tokens,
// and run history, and is the single seam between the HTTP layer and the DB.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("not found")

// Store is the typed handle around a *sql.DB. Methods accept context so
// callers can plumb request timeouts through without wrapping every call.
type Store struct {
	db *sql.DB
}

// Open dials Postgres via pgx's database/sql driver. dsn is a libpq URL,
// e.g. "postgres://concord:dev@localhost:5432/concord?sslmode=disable".
// Open pings the database before returning so misconfiguration surfaces here
// rather than on the first request.
func Open(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging db: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the underlying connection pool.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the raw handle for migrations and exotic queries; prefer
// typed methods for everything else.
func (s *Store) DB() *sql.DB { return s.db }

// migrations is the ordered list of SQL statements that bring an empty
// database up to the current schema. New migrations APPEND; never edit a
// migration that has been applied in any environment.
var migrations = []string{
	`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`,
	`CREATE TABLE IF NOT EXISTS tenants (
		id         UUID PRIMARY KEY,
		name       TEXT NOT NULL,
		slug       TEXT NOT NULL UNIQUE,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`,
	`CREATE TABLE IF NOT EXISTS api_tokens (
		id           UUID PRIMARY KEY,
		tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		token_hash   TEXT NOT NULL UNIQUE,
		name         TEXT NOT NULL,
		created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
		last_used_at TIMESTAMPTZ
	)`,
	`CREATE INDEX IF NOT EXISTS idx_api_tokens_tenant ON api_tokens(tenant_id)`,
	`CREATE TABLE IF NOT EXISTS runs (
		id            UUID PRIMARY KEY,
		tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		status        TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed')),
		started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
		completed_at  TIMESTAMPTZ,
		error_message TEXT,
		summary       JSONB,
		findings      JSONB
	)`,
	`CREATE INDEX IF NOT EXISTS idx_runs_tenant_started ON runs(tenant_id, started_at DESC)`,
}

// Migrate applies any pending migrations. Safe to call on every startup; it
// records applied versions in schema_migrations and never re-applies.
func (s *Store) Migrate(ctx context.Context) error {
	// Always create the migrations table first so the version check below works.
	if _, err := s.db.ExecContext(ctx, migrations[0]); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}
	for i := 1; i < len(migrations); i++ {
		version := i + 1
		var applied bool
		err := s.db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version,
		).Scan(&applied)
		if err != nil {
			return fmt.Errorf("checking migration %d: %w", version, err)
		}
		if applied {
			continue
		}
		if _, err := s.db.ExecContext(ctx, migrations[i]); err != nil {
			return fmt.Errorf("applying migration %d: %w", version, err)
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO schema_migrations(version) VALUES ($1)`, version,
		); err != nil {
			return fmt.Errorf("recording migration %d: %w", version, err)
		}
	}
	return nil
}

// --- Tenants ---

// Tenant is the typed representation of one organization in the database.
type Tenant struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateTenant inserts a tenant and returns it. Slug must be unique.
func (s *Store) CreateTenant(ctx context.Context, name, slug string) (Tenant, error) {
	t := Tenant{ID: uuid.New(), Name: name, Slug: slug}
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO tenants(id, name, slug) VALUES ($1, $2, $3)
		 RETURNING created_at`,
		t.ID, t.Name, t.Slug,
	).Scan(&t.CreatedAt)
	if err != nil {
		return Tenant{}, fmt.Errorf("inserting tenant: %w", err)
	}
	return t, nil
}

// GetTenantBySlug looks up a tenant by its human-readable slug.
func (s *Store) GetTenantBySlug(ctx context.Context, slug string) (Tenant, error) {
	var t Tenant
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, slug, created_at FROM tenants WHERE slug = $1`, slug,
	).Scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	return t, err
}

// GetTenantByID looks up a tenant by ID.
func (s *Store) GetTenantByID(ctx context.Context, id uuid.UUID) (Tenant, error) {
	var t Tenant
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, slug, created_at FROM tenants WHERE id = $1`, id,
	).Scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	return t, err
}

// ListTenants returns every tenant ordered by creation.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, slug, created_at FROM tenants ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// --- API tokens ---

// Token is the metadata kept for one API token. The plaintext is only
// available at creation; thereafter callers see only the hash + metadata.
type Token struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// tokenPrefix is the human-recognisable prefix for every Concord API token.
// Lets operators grep for accidental token leaks in logs / config dumps.
const tokenPrefix = "concord_"

// CreateToken mints a new API token for tenantID. The plaintext token is
// returned ONCE and never stored — callers must capture it. The hash is the
// SHA-256 of the plaintext (hex-encoded), trivial to validate on every request.
func (s *Store) CreateToken(ctx context.Context, tenantID uuid.UUID, name string) (Token, string, error) {
	plaintext, err := generateTokenPlaintext()
	if err != nil {
		return Token{}, "", err
	}
	hash := hashToken(plaintext)
	tok := Token{ID: uuid.New(), TenantID: tenantID, Name: name}
	err = s.db.QueryRowContext(ctx,
		`INSERT INTO api_tokens(id, tenant_id, token_hash, name) VALUES ($1,$2,$3,$4)
		 RETURNING created_at`,
		tok.ID, tok.TenantID, hash, tok.Name,
	).Scan(&tok.CreatedAt)
	if err != nil {
		return Token{}, "", fmt.Errorf("inserting token: %w", err)
	}
	return tok, plaintext, nil
}

// ResolveToken looks up the token row matching plaintext and bumps its
// last_used_at on success. Returns ErrNotFound when the token is unknown.
func (s *Store) ResolveToken(ctx context.Context, plaintext string) (Token, error) {
	hash := hashToken(plaintext)
	var t Token
	err := s.db.QueryRowContext(ctx,
		`UPDATE api_tokens SET last_used_at = now()
		 WHERE token_hash = $1
		 RETURNING id, tenant_id, name, created_at, last_used_at`,
		hash,
	).Scan(&t.ID, &t.TenantID, &t.Name, &t.CreatedAt, &t.LastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	return t, err
}

// ListTokens returns every token belonging to tenantID, newest first.
func (s *Store) ListTokens(ctx context.Context, tenantID uuid.UUID) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, name, created_at, last_used_at
		 FROM api_tokens WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.TenantID, &t.Name, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteToken removes a token by ID.
func (s *Store) DeleteToken(ctx context.Context, tenantID, tokenID uuid.UUID) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM api_tokens WHERE id = $1 AND tenant_id = $2`, tokenID, tenantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Runs ---

// RunStatus enumerates the lifecycle states a run moves through.
type RunStatus string

const (
	RunPending   RunStatus = "pending"
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
)

// Run is the row shape for one evaluation cycle.
type Run struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Status       RunStatus  `json:"status"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
	Summary      []byte     `json:"summary,omitempty"`  // raw JSON
	Findings     []byte     `json:"findings,omitempty"` // raw JSON
}

// CreateRun inserts a new run in pending state.
func (s *Store) CreateRun(ctx context.Context, tenantID uuid.UUID) (Run, error) {
	r := Run{ID: uuid.New(), TenantID: tenantID, Status: RunPending}
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO runs(id, tenant_id, status) VALUES ($1,$2,$3)
		 RETURNING started_at`,
		r.ID, r.TenantID, r.Status,
	).Scan(&r.StartedAt)
	if err != nil {
		return Run{}, err
	}
	return r, nil
}

// MarkRunRunning transitions pending → running.
func (s *Store) MarkRunRunning(ctx context.Context, runID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE runs SET status = 'running' WHERE id = $1`, runID)
	return err
}

// CompleteRun marks the run as succeeded and stores summary + findings JSON.
func (s *Store) CompleteRun(ctx context.Context, runID uuid.UUID, summary, findings []byte) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE runs SET status = 'succeeded', completed_at = now(),
		 summary = $2, findings = $3 WHERE id = $1`,
		runID, summary, findings)
	return err
}

// FailRun marks the run as failed with an error message.
func (s *Store) FailRun(ctx context.Context, runID uuid.UUID, errMsg string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE runs SET status = 'failed', completed_at = now(), error_message = $2
		 WHERE id = $1`, runID, errMsg)
	return err
}

// GetRun fetches a run by ID, scoped to tenantID.
func (s *Store) GetRun(ctx context.Context, tenantID, runID uuid.UUID) (Run, error) {
	var r Run
	err := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, status, started_at, completed_at,
		        COALESCE(error_message,''), summary, findings
		 FROM runs WHERE id = $1 AND tenant_id = $2`,
		runID, tenantID,
	).Scan(&r.ID, &r.TenantID, &r.Status, &r.StartedAt, &r.CompletedAt,
		&r.ErrorMessage, &r.Summary, &r.Findings)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	return r, err
}

// ListRuns returns the last `limit` runs for a tenant, most recent first.
func (s *Store) ListRuns(ctx context.Context, tenantID uuid.UUID, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, status, started_at, completed_at, COALESCE(error_message,'')
		 FROM runs WHERE tenant_id = $1 ORDER BY started_at DESC LIMIT $2`,
		tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Status, &r.StartedAt,
			&r.CompletedAt, &r.ErrorMessage); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Helpers ---

// generateTokenPlaintext returns a 32-byte (256-bit) URL-safe random token
// prefixed with "concord_". 256 bits of entropy makes the token effectively
// unguessable; the hex form is fine for header transport.
func generateTokenPlaintext() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func hashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
