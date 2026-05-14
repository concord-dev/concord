// Package store is the Postgres-backed persistence layer for concord-server.
// It owns the schema (see migrations/*.up.sql), maintains the connection
// pool, and exposes typed CRUD over organizations, users, memberships,
// API tokens, and runs.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("not found")

// PoolOptions tune the pgxpool configuration.
type PoolOptions struct {
	MaxConns        int32         // upper bound on simultaneous connections (default: 8 * GOMAXPROCS, capped by pgx)
	MinConns        int32         // warm pool size (default: 0)
	MaxConnLifetime time.Duration // recycle connections older than this (default: 1h)
	MaxConnIdleTime time.Duration // close idle connections after this (default: 30m)
}

// Store is the typed handle around a pgxpool.Pool.
type Store struct {
	pool *pgxpool.Pool
}

// Open dials Postgres via pgxpool. dsn is a libpq URL, e.g.
// "postgres://concord:dev@localhost:5432/concord?sslmode=disable".
// The pool is health-checked before returning so misconfiguration surfaces
// here rather than on the first request.
func Open(ctx context.Context, dsn string, opts PoolOptions) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing dsn: %w", err)
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		cfg.MinConns = opts.MinConns
	}
	if opts.MaxConnLifetime > 0 {
		cfg.MaxConnLifetime = opts.MaxConnLifetime
	}
	if opts.MaxConnIdleTime > 0 {
		cfg.MaxConnIdleTime = opts.MaxConnIdleTime
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("opening pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging db: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close drains the connection pool. Idempotent.
func (s *Store) Close() { s.pool.Close() }

// Pool exposes the raw pgxpool handle for exotic queries; prefer typed
// methods for everything else.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// --- Organizations ---

// Organization is the typed representation of one customer organization.
type Organization struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateOrganization inserts an org and returns it. Slug must be unique.
func (s *Store) CreateOrganization(ctx context.Context, name, slug string) (Organization, error) {
	o := Organization{Name: name, Slug: slug}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO organizations(name, slug) VALUES ($1, $2)
		 RETURNING id, created_at`,
		name, slug,
	).Scan(&o.ID, &o.CreatedAt)
	if err != nil {
		return Organization{}, fmt.Errorf("inserting organization: %w", err)
	}
	return o, nil
}

// GetOrganizationBySlug looks up an org by its human-readable slug.
func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (Organization, error) {
	var o Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, created_at FROM organizations WHERE slug = $1`, slug,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}

// GetOrganizationByID looks up an org by ID.
func (s *Store) GetOrganizationByID(ctx context.Context, id uuid.UUID) (Organization, error) {
	var o Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, created_at FROM organizations WHERE id = $1`, id,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}

// ListOrganizations returns every organization, oldest first.
func (s *Store) ListOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, slug, created_at FROM organizations ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// --- Users ---

// User is the typed representation of one human principal.
type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateUser inserts a user. Email must be unique (case-insensitive).
func (s *Store) CreateUser(ctx context.Context, email, name string) (User, error) {
	u := User{Email: email, Name: name}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users(email, name) VALUES ($1, $2)
		 RETURNING id, created_at`,
		email, name,
	).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		return User{}, fmt.Errorf("inserting user: %w", err)
	}
	return u, nil
}

// GetUserByID looks up a user by ID.
func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, name, created_at FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &u.Name, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// GetUserByEmail performs a case-insensitive email lookup.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, name, created_at FROM users WHERE lower(email) = lower($1)`, email,
	).Scan(&u.ID, &u.Email, &u.Name, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// ListUsers returns every user.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, email, name, created_at FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// --- Memberships ---

// Role enumerates the role values a membership row can carry. Mirrored in the
// CHECK constraint on memberships.role so application + DB stay aligned.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

// ValidRoles returns the canonical role list. Used by handlers to validate
// requested role strings.
func ValidRoles() []Role { return []Role{RoleOwner, RoleAdmin, RoleMember, RoleViewer} }

// IsValid reports whether r is one of the canonical roles.
func (r Role) IsValid() bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleMember, RoleViewer:
		return true
	}
	return false
}

// Permits reports whether the holder of this role may perform a min-role
// action. Hierarchy: owner > admin > member > viewer. Action "owner" requires
// owner, "admin" requires admin or owner, etc.
func (r Role) Permits(needed Role) bool {
	rank := map[Role]int{RoleViewer: 0, RoleMember: 1, RoleAdmin: 2, RoleOwner: 3}
	return rank[r] >= rank[needed]
}

// Membership ties a user to an organization with a role.
type Membership struct {
	UserID    uuid.UUID `json:"user_id"`
	OrgID     uuid.UUID `json:"org_id"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// AddMember creates or updates the membership for (userID, orgID) and sets
// its role. Upsert semantics keep the operation idempotent.
func (s *Store) AddMember(ctx context.Context, userID, orgID uuid.UUID, role Role) (Membership, error) {
	if !role.IsValid() {
		return Membership{}, fmt.Errorf("invalid role %q", role)
	}
	var m Membership
	err := s.pool.QueryRow(ctx,
		`INSERT INTO memberships(user_id, org_id, role) VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, org_id) DO UPDATE SET role = EXCLUDED.role
		 RETURNING user_id, org_id, role, created_at`,
		userID, orgID, string(role),
	).Scan(&m.UserID, &m.OrgID, &m.Role, &m.CreatedAt)
	return m, err
}

// RemoveMember deletes the membership row.
func (s *Store) RemoveMember(ctx context.Context, userID, orgID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM memberships WHERE user_id = $1 AND org_id = $2`, userID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetMembership returns the membership row for (userID, orgID).
func (s *Store) GetMembership(ctx context.Context, userID, orgID uuid.UUID) (Membership, error) {
	var m Membership
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, org_id, role, created_at FROM memberships
		 WHERE user_id = $1 AND org_id = $2`, userID, orgID,
	).Scan(&m.UserID, &m.OrgID, &m.Role, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrNotFound
	}
	return m, err
}

// ListOrgMembers returns every membership for the given organization joined
// with user details. The result is sorted by role rank (owner first) then
// email.
type OrgMember struct {
	User       User      `json:"user"`
	Role       Role      `json:"role"`
	JoinedAt   time.Time `json:"joined_at"`
}

func (s *Store) ListOrgMembers(ctx context.Context, orgID uuid.UUID) ([]OrgMember, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT u.id, u.email, u.name, u.created_at, m.role, m.created_at
		 FROM memberships m
		 JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1
		 ORDER BY
		   CASE m.role
		     WHEN 'owner' THEN 0 WHEN 'admin' THEN 1
		     WHEN 'member' THEN 2 WHEN 'viewer' THEN 3
		   END,
		   lower(u.email)`,
		orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrgMember
	for rows.Next() {
		var om OrgMember
		if err := rows.Scan(&om.User.ID, &om.User.Email, &om.User.Name, &om.User.CreatedAt,
			&om.Role, &om.JoinedAt); err != nil {
			return nil, err
		}
		out = append(out, om)
	}
	return out, rows.Err()
}

// ListUserOrgs returns every org the user belongs to, with their role.
type UserOrg struct {
	Organization Organization `json:"organization"`
	Role         Role         `json:"role"`
}

func (s *Store) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]UserOrg, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT o.id, o.name, o.slug, o.created_at, m.role
		 FROM memberships m
		 JOIN organizations o ON o.id = m.org_id
		 WHERE m.user_id = $1
		 ORDER BY o.created_at ASC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserOrg
	for rows.Next() {
		var uo UserOrg
		if err := rows.Scan(&uo.Organization.ID, &uo.Organization.Name,
			&uo.Organization.Slug, &uo.Organization.CreatedAt, &uo.Role); err != nil {
			return nil, err
		}
		out = append(out, uo)
	}
	return out, rows.Err()
}

// --- API tokens ---

// Token is the metadata kept for one API token.
type Token struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	Name       string     `json:"name"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// tokenPrefix is the human-recognisable prefix for every Concord API token.
const tokenPrefix = "concord_"

// CreateToken mints a new API token for orgID. The plaintext is returned ONCE
// and never stored. createdBy may be nil when the token is minted by the
// admin-bootstrap operator (no user identity yet).
func (s *Store) CreateToken(ctx context.Context, orgID uuid.UUID, name string, createdBy *uuid.UUID) (Token, string, error) {
	plaintext, err := generateTokenPlaintext()
	if err != nil {
		return Token{}, "", err
	}
	hash := hashToken(plaintext)
	var t Token
	err = s.pool.QueryRow(ctx,
		`INSERT INTO api_tokens(org_id, token_hash, name, created_by) VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, name, created_by, created_at`,
		orgID, hash, name, createdBy,
	).Scan(&t.ID, &t.OrgID, &t.Name, &t.CreatedBy, &t.CreatedAt)
	if err != nil {
		return Token{}, "", fmt.Errorf("inserting token: %w", err)
	}
	return t, plaintext, nil
}

// ResolveToken looks up the token row matching plaintext and bumps its
// last_used_at on success. Returns ErrNotFound when the token is unknown.
func (s *Store) ResolveToken(ctx context.Context, plaintext string) (Token, error) {
	hash := hashToken(plaintext)
	var t Token
	err := s.pool.QueryRow(ctx,
		`UPDATE api_tokens SET last_used_at = now()
		 WHERE token_hash = $1
		 RETURNING id, org_id, name, created_by, created_at, last_used_at`,
		hash,
	).Scan(&t.ID, &t.OrgID, &t.Name, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	return t, err
}

// ListTokens returns every token belonging to orgID, newest first.
func (s *Store) ListTokens(ctx context.Context, orgID uuid.UUID) ([]Token, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, name, created_by, created_at, last_used_at
		 FROM api_tokens WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteToken removes a token. Scoped to orgID so tenants cannot delete
// tokens that belong to other organizations.
func (s *Store) DeleteToken(ctx context.Context, orgID, tokenID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM api_tokens WHERE id = $1 AND org_id = $2`, tokenID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
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
	ID                uuid.UUID  `json:"id"`
	OrgID             uuid.UUID  `json:"org_id"`
	Status            RunStatus  `json:"status"`
	StartedAt         time.Time  `json:"started_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	ErrorMessage      string     `json:"error_message,omitempty"`
	Summary           []byte     `json:"summary,omitempty"`  // raw JSON
	Findings          []byte     `json:"findings,omitempty"` // raw JSON
	TriggeredByToken  *uuid.UUID `json:"triggered_by_token,omitempty"`
}

// CreateRun inserts a new run in pending state.
func (s *Store) CreateRun(ctx context.Context, orgID uuid.UUID, tokenID *uuid.UUID) (Run, error) {
	r := Run{OrgID: orgID, Status: RunPending, TriggeredByToken: tokenID}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO runs(org_id, status, triggered_by_token) VALUES ($1, $2, $3)
		 RETURNING id, started_at`,
		orgID, string(r.Status), tokenID,
	).Scan(&r.ID, &r.StartedAt)
	return r, err
}

// MarkRunRunning transitions pending → running.
func (s *Store) MarkRunRunning(ctx context.Context, runID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE runs SET status = 'running' WHERE id = $1`, runID)
	return err
}

// CompleteRun marks the run as succeeded and stores summary + findings JSON.
func (s *Store) CompleteRun(ctx context.Context, runID uuid.UUID, summary, findings []byte) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE runs SET status = 'succeeded', completed_at = now(),
		 summary = $2, findings = $3 WHERE id = $1`,
		runID, summary, findings)
	return err
}

// FailRun marks the run as failed with an error message.
func (s *Store) FailRun(ctx context.Context, runID uuid.UUID, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE runs SET status = 'failed', completed_at = now(), error_message = $2
		 WHERE id = $1`, runID, errMsg)
	return err
}

// GetRun fetches a run by ID, scoped to orgID.
func (s *Store) GetRun(ctx context.Context, orgID, runID uuid.UUID) (Run, error) {
	var r Run
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, status, started_at, completed_at,
		        COALESCE(error_message,''), summary, findings, triggered_by_token
		 FROM runs WHERE id = $1 AND org_id = $2`,
		runID, orgID,
	).Scan(&r.ID, &r.OrgID, &r.Status, &r.StartedAt, &r.CompletedAt,
		&r.ErrorMessage, &r.Summary, &r.Findings, &r.TriggeredByToken)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	return r, err
}

// ListRuns returns the last `limit` runs for an organization, newest first.
func (s *Store) ListRuns(ctx context.Context, orgID uuid.UUID, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, status, started_at, completed_at, COALESCE(error_message,''), triggered_by_token
		 FROM runs WHERE org_id = $1 ORDER BY started_at DESC LIMIT $2`,
		orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Status, &r.StartedAt,
			&r.CompletedAt, &r.ErrorMessage, &r.TriggeredByToken); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Helpers ---

// generateTokenPlaintext returns a 32-byte (256-bit) URL-safe random token
// prefixed with "concord_". 256 bits of entropy makes the token effectively
// unguessable.
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
