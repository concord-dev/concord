// Package store is the Postgres-backed persistence layer for concord-server.
// It owns the schema (see migrations/*.up.sql), maintains the connection
// pool, and exposes typed CRUD over the RBAC + domain tables:
//
//	organization, "user", role, permission, role_permission, user_org_role,
//	api_token, user_session, run
//
// The package is the single seam between the HTTP layer and Postgres.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/concord-dev/concord/internal/auth"
)

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("not found")

// PoolOptions tune the pgxpool configuration.
type PoolOptions struct {
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// Store is the typed handle around a pgxpool.Pool.
type Store struct {
	pool *pgxpool.Pool
}

// Open dials Postgres via pgxpool. dsn is a libpq URL. The pool is
// health-checked before returning so misconfiguration surfaces immediately.
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

// ─── Organizations ──────────────────────────────────────────────────────

// Organization is one customer organization.
type Organization struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateOrganization inserts an org and returns it. Slug must be unique.
func (s *Store) CreateOrganization(ctx context.Context, name, slug string) (Organization, error) {
	var o Organization
	err := s.pool.QueryRow(ctx,
		`INSERT INTO organization(name, slug) VALUES ($1, $2)
		 RETURNING id, name, slug, created_at, updated_at`,
		name, slug,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return Organization{}, fmt.Errorf("inserting organization: %w", err)
	}
	return o, nil
}

// GetOrganizationBySlug looks up an org by its human-readable slug.
func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (Organization, error) {
	var o Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, created_at, updated_at FROM organization WHERE slug = $1`, slug,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}

// GetOrganizationByID looks up an org by ID.
func (s *Store) GetOrganizationByID(ctx context.Context, id uuid.UUID) (Organization, error) {
	var o Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, created_at, updated_at FROM organization WHERE id = $1`, id,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}

// ListOrganizations returns every organization, oldest first.
func (s *Store) ListOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, slug, created_at, updated_at FROM organization ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ─── Users ──────────────────────────────────────────────────────────────

// User is one human principal. Email + password drive web login; users
// without a password_hash are invite-pending or SSO-only.
type User struct {
	ID              uuid.UUID  `json:"id"`
	FirstName       string     `json:"first_name"`
	LastName        string     `json:"last_name"`
	Email           string     `json:"email"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// CreateUserParams is the input for CreateUser. Password may be empty for
// invite-pending users; the password_hash column stays NULL in that case.
type CreateUserParams struct {
	FirstName string
	LastName  string
	Email     string
	Password  string // optional
}

// CreateUser inserts a user. Email must be unique (case-insensitive). When
// Password is set, it is hashed with argon2id before insertion.
func (s *Store) CreateUser(ctx context.Context, p CreateUserParams) (User, error) {
	if p.FirstName == "" || p.LastName == "" || p.Email == "" {
		return User{}, errors.New("first_name, last_name, and email are required")
	}
	var pwHash *string
	if p.Password != "" {
		h, err := auth.HashPassword(p.Password)
		if err != nil {
			return User{}, err
		}
		pwHash = &h
	}
	var u User
	err := s.pool.QueryRow(ctx,
		`INSERT INTO "user"(first_name, last_name, email, password_hash)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, first_name, last_name, email, email_verified_at, created_at, updated_at`,
		p.FirstName, p.LastName, p.Email, pwHash,
	).Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return User{}, fmt.Errorf("inserting user: %w", err)
	}
	return u, nil
}

// GetUserByID looks up a user by ID.
func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, first_name, last_name, email, email_verified_at, created_at, updated_at
		 FROM "user" WHERE id = $1`, id,
	).Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// GetUserByEmail performs a case-insensitive email lookup.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, first_name, last_name, email, email_verified_at, created_at, updated_at
		 FROM "user" WHERE lower(email) = lower($1)`, email,
	).Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// VerifyUserPassword loads the user's password_hash, runs argon2id against
// plaintext, and returns the user record on success. Used by the login handler.
func (s *Store) VerifyUserPassword(ctx context.Context, email, plaintext string) (User, error) {
	var u User
	var hash *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, first_name, last_name, email, email_verified_at, created_at, updated_at, password_hash
		 FROM "user" WHERE lower(email) = lower($1)`, email,
	).Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	if hash == nil {
		return User{}, ErrNotFound
	}
	ok, err := auth.VerifyPassword(plaintext, *hash)
	if err != nil {
		return User{}, fmt.Errorf("verifying password: %w", err)
	}
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

// ListUsers returns every user.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, first_name, last_name, email, email_verified_at, created_at, updated_at
		 FROM "user" ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email,
			&u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ─── Roles + permissions ────────────────────────────────────────────────

// Role is a named bundle of permissions. Roles are data, not enum — new
// roles can be added at runtime without code changes.
type Role struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Permission is one atomic capability, e.g. "runs:create".
type Permission struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GetRoleByName returns the role identified by its name.
func (s *Store) GetRoleByName(ctx context.Context, name string) (Role, error) {
	var r Role
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, created_at, updated_at FROM role WHERE name = $1`, name,
	).Scan(&r.ID, &r.Name, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Role{}, ErrNotFound
	}
	return r, err
}

// ListRoles returns every role, alphabetical.
func (s *Store) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, created_at, updated_at FROM role ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.Name, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListPermissions returns every defined permission.
func (s *Store) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, created_at, updated_at FROM permission ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListRolePermissions returns every permission attached to roleID.
func (s *Store) ListRolePermissions(ctx context.Context, roleID uuid.UUID) ([]Permission, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT p.id, p.name, p.created_at, p.updated_at
		 FROM permission p
		 JOIN role_permission rp ON rp.permission_id = p.id
		 WHERE rp.role_id = $1
		 ORDER BY p.name`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ─── Memberships (user_org_role) ────────────────────────────────────────

// AssignRole grants a role to a user inside an org. Idempotent — re-assigning
// the same triple is a no-op (the PK collides and ON CONFLICT skips).
func (s *Store) AssignRole(ctx context.Context, userID, orgID, roleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_org_role(user_id, org_id, role_id)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		userID, orgID, roleID)
	return err
}

// RevokeRole removes one specific role grant.
func (s *Store) RevokeRole(ctx context.Context, userID, orgID, roleID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM user_org_role WHERE user_id = $1 AND org_id = $2 AND role_id = $3`,
		userID, orgID, roleID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveUserFromOrg drops every role grant for (userID, orgID).
func (s *Store) RemoveUserFromOrg(ctx context.Context, userID, orgID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM user_org_role WHERE user_id = $1 AND org_id = $2`, userID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// OrgMember is one (user, org) pair with the roles the user holds in that org.
type OrgMember struct {
	User  User   `json:"user"`
	Roles []Role `json:"roles"`
}

// ListOrgMembers returns every member of orgID, grouped by user so the
// multiple roles a user holds appear together.
func (s *Store) ListOrgMembers(ctx context.Context, orgID uuid.UUID) ([]OrgMember, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT u.id, u.first_name, u.last_name, u.email, u.email_verified_at,
		        u.created_at, u.updated_at,
		        r.id, r.name, r.created_at, r.updated_at
		 FROM user_org_role uor
		 JOIN "user" u ON u.id = uor.user_id
		 JOIN role r ON r.id = uor.role_id
		 WHERE uor.org_id = $1
		 ORDER BY lower(u.email), r.name`,
		orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byUser := make(map[uuid.UUID]*OrgMember)
	order := []uuid.UUID{}
	for rows.Next() {
		var u User
		var r Role
		if err := rows.Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.EmailVerifiedAt,
			&u.CreatedAt, &u.UpdatedAt,
			&r.ID, &r.Name, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		m, ok := byUser[u.ID]
		if !ok {
			m = &OrgMember{User: u}
			byUser[u.ID] = m
			order = append(order, u.ID)
		}
		m.Roles = append(m.Roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]OrgMember, 0, len(order))
	for _, id := range order {
		out = append(out, *byUser[id])
	}
	return out, nil
}

// UserOrg is one org a user belongs to, with the roles they hold there.
type UserOrg struct {
	Organization Organization `json:"organization"`
	Roles        []Role       `json:"roles"`
}

// ListUserOrgs returns every org the user belongs to with the roles they hold.
func (s *Store) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]UserOrg, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT o.id, o.name, o.slug, o.created_at, o.updated_at,
		        r.id, r.name, r.created_at, r.updated_at
		 FROM user_org_role uor
		 JOIN organization o ON o.id = uor.org_id
		 JOIN role r ON r.id = uor.role_id
		 WHERE uor.user_id = $1
		 ORDER BY o.created_at, r.name`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byOrg := make(map[uuid.UUID]*UserOrg)
	order := []uuid.UUID{}
	for rows.Next() {
		var o Organization
		var r Role
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt,
			&r.ID, &r.Name, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		entry, ok := byOrg[o.ID]
		if !ok {
			entry = &UserOrg{Organization: o}
			byOrg[o.ID] = entry
			order = append(order, o.ID)
		}
		entry.Roles = append(entry.Roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]UserOrg, 0, len(order))
	for _, id := range order {
		out = append(out, *byOrg[id])
	}
	return out, nil
}

// HasPermission reports whether the user holds any role in the org that
// grants the named permission. Returns false (no error) when the user has
// no membership in the org.
func (s *Store) HasPermission(ctx context.Context, userID, orgID uuid.UUID, permission string) (bool, error) {
	var got bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1
		    FROM user_org_role uor
		    JOIN role_permission rp ON rp.role_id = uor.role_id
		    JOIN permission p       ON p.id = rp.permission_id
		    WHERE uor.user_id = $1 AND uor.org_id = $2 AND p.name = $3
		 )`,
		userID, orgID, permission,
	).Scan(&got)
	return got, err
}

// UserPermissions returns the distinct permission names the user holds in
// the org. Useful for "what can this user do here?" UI prompts.
func (s *Store) UserPermissions(ctx context.Context, userID, orgID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT p.name
		 FROM user_org_role uor
		 JOIN role_permission rp ON rp.role_id = uor.role_id
		 JOIN permission p       ON p.id = rp.permission_id
		 WHERE uor.user_id = $1 AND uor.org_id = $2
		 ORDER BY p.name`,
		userID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ─── API tokens ─────────────────────────────────────────────────────────

// APIToken is the long-lived programmatic credential. Token plaintext is
// returned only at creation; thereafter only hash + metadata persist.
type APIToken struct {
	ID              uuid.UUID  `json:"id"`
	OrgID           uuid.UUID  `json:"org_id"`
	Name            string     `json:"name"`
	CreatedByUserID *uuid.UUID `json:"created_by_user_id,omitempty"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// CreateAPIToken mints a new programmatic token. createdBy may be nil when
// the token is minted via the admin-bootstrap path (no user identity yet).
func (s *Store) CreateAPIToken(ctx context.Context, orgID uuid.UUID, name string, createdBy *uuid.UUID) (APIToken, string, error) {
	plaintext, err := auth.GenerateSecret(auth.APITokenPrefix, 32)
	if err != nil {
		return APIToken{}, "", err
	}
	hash := auth.HashSecret(plaintext)
	var t APIToken
	err = s.pool.QueryRow(ctx,
		`INSERT INTO api_token(org_id, token_hash, name, created_by_user_id)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, org_id, name, created_by_user_id, last_used_at, revoked_at, created_at, updated_at`,
		orgID, hash, name, createdBy,
	).Scan(&t.ID, &t.OrgID, &t.Name, &t.CreatedByUserID,
		&t.LastUsedAt, &t.RevokedAt, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return APIToken{}, "", fmt.Errorf("inserting api_token: %w", err)
	}
	return t, plaintext, nil
}

// ResolveAPIToken looks up the token row matching plaintext, ignoring revoked
// rows, and bumps last_used_at on success. Returns ErrNotFound when the
// token is unknown or has been revoked.
func (s *Store) ResolveAPIToken(ctx context.Context, plaintext string) (APIToken, error) {
	hash := auth.HashSecret(plaintext)
	var t APIToken
	err := s.pool.QueryRow(ctx,
		`UPDATE api_token SET last_used_at = now()
		 WHERE token_hash = $1 AND revoked_at IS NULL
		 RETURNING id, org_id, name, created_by_user_id, last_used_at, revoked_at, created_at, updated_at`,
		hash,
	).Scan(&t.ID, &t.OrgID, &t.Name, &t.CreatedByUserID,
		&t.LastUsedAt, &t.RevokedAt, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIToken{}, ErrNotFound
	}
	return t, err
}

// ListAPITokens returns every non-revoked token belonging to orgID, newest first.
func (s *Store) ListAPITokens(ctx context.Context, orgID uuid.UUID) ([]APIToken, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, name, created_by_user_id, last_used_at, revoked_at, created_at, updated_at
		 FROM api_token WHERE org_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.CreatedByUserID,
			&t.LastUsedAt, &t.RevokedAt, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken marks a token as revoked. Soft-delete so historical runs
// retain the FK reference (triggered_by_token).
func (s *Store) RevokeAPIToken(ctx context.Context, orgID, tokenID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE api_token SET revoked_at = now()
		 WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`,
		tokenID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── User sessions ──────────────────────────────────────────────────────

// Session is one browser session. The plaintext token is returned only at
// creation; the row stores its sha256 hash. IP is read back via INET::text
// because pgx's default codec for netip.Addr in nullable columns isn't
// reliable across versions — string round-trips cleanly.
type Session struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	IP         string     `json:"ip,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// CreateSession mints a new session token for userID. ttl is how long the
// session is valid (typical: 24h–7d). ip/userAgent are recorded for the
// "active sessions" UI; either may be empty. ip must parse as INET or
// Postgres rejects the insert — pass an empty string when unknown.
func (s *Store) CreateSession(ctx context.Context, userID uuid.UUID, ttl time.Duration, ip, userAgent string) (Session, string, error) {
	plaintext, err := auth.GenerateSecret(auth.SessionTokenPrefix, 32)
	if err != nil {
		return Session{}, "", err
	}
	hash := auth.HashSecret(plaintext)
	expires := time.Now().UTC().Add(ttl)

	var sess Session
	err = s.pool.QueryRow(ctx,
		`INSERT INTO user_session(user_id, token_hash, expires_at, ip, user_agent)
		 VALUES ($1, $2, $3, NULLIF($4,'')::inet, NULLIF($5,''))
		 RETURNING id, user_id, expires_at, last_used_at, revoked_at,
		           COALESCE(host(ip), ''), COALESCE(user_agent,''), created_at`,
		userID, hash, expires, ip, userAgent,
	).Scan(&sess.ID, &sess.UserID, &sess.ExpiresAt, &sess.LastUsedAt,
		&sess.RevokedAt, &sess.IP, &sess.UserAgent, &sess.CreatedAt)
	if err != nil {
		return Session{}, "", fmt.Errorf("inserting session: %w", err)
	}
	return sess, plaintext, nil
}

// ResolveSession looks up an active (non-expired, non-revoked) session by
// plaintext token and bumps last_used_at.
func (s *Store) ResolveSession(ctx context.Context, plaintext string) (Session, error) {
	hash := auth.HashSecret(plaintext)
	var sess Session
	err := s.pool.QueryRow(ctx,
		`UPDATE user_session SET last_used_at = now()
		 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
		 RETURNING id, user_id, expires_at, last_used_at, revoked_at,
		           COALESCE(host(ip), ''), COALESCE(user_agent,''), created_at`,
		hash,
	).Scan(&sess.ID, &sess.UserID, &sess.ExpiresAt, &sess.LastUsedAt,
		&sess.RevokedAt, &sess.IP, &sess.UserAgent, &sess.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return sess, err
}

// RevokeSession marks a single session as revoked.
func (s *Store) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE user_session SET revoked_at = now()
		 WHERE id = $1 AND revoked_at IS NULL`, sessionID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeAllSessionsForUser invalidates every active session for a user;
// invoked on password change or admin-revoke.
func (s *Store) RevokeAllSessionsForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE user_session SET revoked_at = now()
		 WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

// ─── Control overrides ─────────────────────────────────────────────────

// ControlOverride is a per-org Rego parameter override for a single control.
// Params is the same JSON shape the local concord.yaml writes — a flat
// string-keyed map. NULL params is forbidden by the schema; callers that
// want to "remove" an override should DELETE the row.
type ControlOverride struct {
	ID        uuid.UUID `json:"id"`
	OrgID     uuid.UUID `json:"org_id"`
	ControlID string    `json:"control_id"`
	Params    []byte    `json:"params"` // raw JSON
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpsertControlOverride sets (or replaces) the params for (orgID, controlID).
// params must be a JSON-encoded object; the column has a JSONB type.
func (s *Store) UpsertControlOverride(ctx context.Context, orgID uuid.UUID, controlID string, params []byte) (ControlOverride, error) {
	if controlID == "" {
		return ControlOverride{}, errors.New("control_id is required")
	}
	if len(params) == 0 {
		return ControlOverride{}, errors.New("params must be a JSON object; pass {} for empty")
	}
	var co ControlOverride
	err := s.pool.QueryRow(ctx,
		`INSERT INTO control_override(org_id, control_id, params)
		 VALUES ($1, $2, $3::jsonb)
		 ON CONFLICT (org_id, control_id) DO UPDATE
		   SET params = EXCLUDED.params, updated_at = now()
		 RETURNING id, org_id, control_id, params, created_at, updated_at`,
		orgID, controlID, params,
	).Scan(&co.ID, &co.OrgID, &co.ControlID, &co.Params, &co.CreatedAt, &co.UpdatedAt)
	if err != nil {
		return ControlOverride{}, fmt.Errorf("upserting control override: %w", err)
	}
	return co, nil
}

// GetControlOverride returns the override for one control, or ErrNotFound.
func (s *Store) GetControlOverride(ctx context.Context, orgID uuid.UUID, controlID string) (ControlOverride, error) {
	var co ControlOverride
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, control_id, params, created_at, updated_at
		 FROM control_override WHERE org_id = $1 AND control_id = $2`,
		orgID, controlID,
	).Scan(&co.ID, &co.OrgID, &co.ControlID, &co.Params, &co.CreatedAt, &co.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ControlOverride{}, ErrNotFound
	}
	return co, err
}

// ListControlOverrides returns every override row for orgID, sorted by control id.
func (s *Store) ListControlOverrides(ctx context.Context, orgID uuid.UUID) ([]ControlOverride, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, control_id, params, created_at, updated_at
		 FROM control_override WHERE org_id = $1 ORDER BY control_id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ControlOverride
	for rows.Next() {
		var co ControlOverride
		if err := rows.Scan(&co.ID, &co.OrgID, &co.ControlID, &co.Params,
			&co.CreatedAt, &co.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, co)
	}
	return out, rows.Err()
}

// DeleteControlOverride removes the row. Returns ErrNotFound when no row matched.
func (s *Store) DeleteControlOverride(ctx context.Context, orgID uuid.UUID, controlID string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM control_override WHERE org_id = $1 AND control_id = $2`,
		orgID, controlID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ControlParamsForOrg returns the per-control params map an org has on file,
// in the shape the runner.SetParams() expects:
//
//	map[control_id]map[param_name]value
//
// Decodes every override's JSONB into a Go map. Errors if any row's JSON is
// malformed — that's a data-integrity issue worth surfacing.
func (s *Store) ControlParamsForOrg(ctx context.Context, orgID uuid.UUID) (map[string]map[string]any, error) {
	overrides, err := s.ListControlOverrides(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]any, len(overrides))
	for _, co := range overrides {
		var p map[string]any
		if err := json.Unmarshal(co.Params, &p); err != nil {
			return nil, fmt.Errorf("decoding params for %s: %w", co.ControlID, err)
		}
		out[co.ControlID] = p
	}
	return out, nil
}

// ─── Webhooks ──────────────────────────────────────────────────────────

// Webhook is one outbound HTTP delivery target. Each webhook has its own
// signing secret; a leaked secret only affects that one destination.
type Webhook struct {
	ID          uuid.UUID  `json:"id"`
	OrgID       uuid.UUID  `json:"org_id"`
	URL         string     `json:"url"`
	Secret      string     `json:"secret,omitempty"` // omitted from list/get for safety
	EventKinds  []string   `json:"event_kinds"`
	Enabled     bool       `json:"enabled"`
	LastFiredAt *time.Time `json:"last_fired_at,omitempty"`
	LastStatus  *int       `json:"last_status,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// CreateWebhookParams is the input for CreateWebhook. Secret is generated by
// the store if left empty so callers don't have to think about entropy.
type CreateWebhookParams struct {
	OrgID      uuid.UUID
	URL        string
	Secret     string
	EventKinds []string
	Enabled    bool
}

// CreateWebhook inserts a new webhook row. Returns the row plus the plaintext
// secret (caller must surface it to the user once — the secret is required
// to verify HMAC signatures).
func (s *Store) CreateWebhook(ctx context.Context, p CreateWebhookParams) (Webhook, string, error) {
	if p.URL == "" {
		return Webhook{}, "", errors.New("url is required")
	}
	if p.Secret == "" {
		secret, err := auth.GenerateSecret("whsec_", 24)
		if err != nil {
			return Webhook{}, "", err
		}
		p.Secret = secret
	}
	kinds := p.EventKinds
	if kinds == nil {
		kinds = []string{}
	}
	var wh Webhook
	err := s.pool.QueryRow(ctx,
		`INSERT INTO webhook(org_id, url, secret, event_kinds, enabled)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, org_id, url, secret, event_kinds, enabled,
		           last_fired_at, last_status, COALESCE(last_error,''), created_at, updated_at`,
		p.OrgID, p.URL, p.Secret, kinds, p.Enabled,
	).Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Secret, &wh.EventKinds, &wh.Enabled,
		&wh.LastFiredAt, &wh.LastStatus, &wh.LastError, &wh.CreatedAt, &wh.UpdatedAt)
	if err != nil {
		return Webhook{}, "", fmt.Errorf("inserting webhook: %w", err)
	}
	return wh, p.Secret, nil
}

// GetWebhook returns a single webhook scoped to orgID.
func (s *Store) GetWebhook(ctx context.Context, orgID, id uuid.UUID) (Webhook, error) {
	var wh Webhook
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, url, secret, event_kinds, enabled,
		        last_fired_at, last_status, COALESCE(last_error,''), created_at, updated_at
		 FROM webhook WHERE id = $1 AND org_id = $2`,
		id, orgID,
	).Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Secret, &wh.EventKinds, &wh.Enabled,
		&wh.LastFiredAt, &wh.LastStatus, &wh.LastError, &wh.CreatedAt, &wh.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Webhook{}, ErrNotFound
	}
	return wh, err
}

// ListWebhooks returns every webhook for orgID, newest first.
func (s *Store) ListWebhooks(ctx context.Context, orgID uuid.UUID) ([]Webhook, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, url, secret, event_kinds, enabled,
		        last_fired_at, last_status, COALESCE(last_error,''), created_at, updated_at
		 FROM webhook WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		var wh Webhook
		if err := rows.Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Secret, &wh.EventKinds, &wh.Enabled,
			&wh.LastFiredAt, &wh.LastStatus, &wh.LastError, &wh.CreatedAt, &wh.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, wh)
	}
	return out, rows.Err()
}

// ListEnabledWebhooks returns the active webhooks for orgID — the lookup
// path the worker takes on every event publish. Disabled rows are skipped.
func (s *Store) ListEnabledWebhooks(ctx context.Context, orgID uuid.UUID) ([]Webhook, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, url, secret, event_kinds, enabled,
		        last_fired_at, last_status, COALESCE(last_error,''), created_at, updated_at
		 FROM webhook WHERE org_id = $1 AND enabled = true`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		var wh Webhook
		if err := rows.Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Secret, &wh.EventKinds, &wh.Enabled,
			&wh.LastFiredAt, &wh.LastStatus, &wh.LastError, &wh.CreatedAt, &wh.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, wh)
	}
	return out, rows.Err()
}

// UpdateWebhookParams carries the fields a PUT may update. Pointers
// distinguish "leave unchanged" (nil) from "set to this value".
type UpdateWebhookParams struct {
	URL        *string
	EventKinds *[]string
	Enabled    *bool
}

// UpdateWebhook patches the writable fields of a webhook. Secret is
// intentionally not patchable here — secret rotation is a separate flow.
func (s *Store) UpdateWebhook(ctx context.Context, orgID, id uuid.UUID, p UpdateWebhookParams) (Webhook, error) {
	current, err := s.GetWebhook(ctx, orgID, id)
	if err != nil {
		return Webhook{}, err
	}
	if p.URL != nil {
		current.URL = *p.URL
	}
	if p.EventKinds != nil {
		current.EventKinds = *p.EventKinds
	}
	if p.Enabled != nil {
		current.Enabled = *p.Enabled
	}
	var wh Webhook
	err = s.pool.QueryRow(ctx,
		`UPDATE webhook SET url = $3, event_kinds = $4, enabled = $5, updated_at = now()
		 WHERE id = $1 AND org_id = $2
		 RETURNING id, org_id, url, secret, event_kinds, enabled,
		           last_fired_at, last_status, COALESCE(last_error,''), created_at, updated_at`,
		id, orgID, current.URL, current.EventKinds, current.Enabled,
	).Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Secret, &wh.EventKinds, &wh.Enabled,
		&wh.LastFiredAt, &wh.LastStatus, &wh.LastError, &wh.CreatedAt, &wh.UpdatedAt)
	return wh, err
}

// DeleteWebhook removes the row.
func (s *Store) DeleteWebhook(ctx context.Context, orgID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM webhook WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordWebhookResult stamps the delivery outcome on the row so operators
// can see "this webhook returned 502 last time" in the dashboard. errMsg may
// be empty on successful delivery.
func (s *Store) RecordWebhookResult(ctx context.Context, id uuid.UUID, status int, errMsg string) error {
	var errPtr *string
	if errMsg != "" {
		errPtr = &errMsg
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE webhook SET last_fired_at = now(), last_status = $2, last_error = $3, updated_at = now()
		 WHERE id = $1`, id, status, errPtr)
	return err
}

// ─── Schedules ─────────────────────────────────────────────────────────

// Schedule is one cron-driven trigger for an organization's compliance runs.
// Exactly one row per org (UNIQUE enforces it); set enabled=false to pause
// without losing the cron expression.
type Schedule struct {
	ID          uuid.UUID  `json:"id"`
	OrgID       uuid.UUID  `json:"org_id"`
	CronExpr    string     `json:"cron_expr"`
	Enabled     bool       `json:"enabled"`
	LastFiredAt *time.Time `json:"last_fired_at,omitempty"`
	NextFireAt  time.Time  `json:"next_fire_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// UpsertSchedule replaces (or creates) the schedule row for an org. The
// caller is responsible for computing nextFireAt from the cron expression —
// the store layer does not know about cron parsing.
func (s *Store) UpsertSchedule(ctx context.Context, orgID uuid.UUID, cronExpr string, enabled bool, nextFireAt time.Time) (Schedule, error) {
	if cronExpr == "" {
		return Schedule{}, errors.New("cron_expr is required")
	}
	var sch Schedule
	err := s.pool.QueryRow(ctx,
		`INSERT INTO schedule(org_id, cron_expr, enabled, next_fire_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (org_id) DO UPDATE SET
		   cron_expr = EXCLUDED.cron_expr,
		   enabled = EXCLUDED.enabled,
		   next_fire_at = EXCLUDED.next_fire_at,
		   updated_at = now()
		 RETURNING id, org_id, cron_expr, enabled, last_fired_at, next_fire_at, created_at, updated_at`,
		orgID, cronExpr, enabled, nextFireAt,
	).Scan(&sch.ID, &sch.OrgID, &sch.CronExpr, &sch.Enabled,
		&sch.LastFiredAt, &sch.NextFireAt, &sch.CreatedAt, &sch.UpdatedAt)
	if err != nil {
		return Schedule{}, fmt.Errorf("upserting schedule: %w", err)
	}
	return sch, nil
}

// GetSchedule returns the schedule for orgID, or ErrNotFound.
func (s *Store) GetSchedule(ctx context.Context, orgID uuid.UUID) (Schedule, error) {
	var sch Schedule
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, cron_expr, enabled, last_fired_at, next_fire_at, created_at, updated_at
		 FROM schedule WHERE org_id = $1`, orgID,
	).Scan(&sch.ID, &sch.OrgID, &sch.CronExpr, &sch.Enabled,
		&sch.LastFiredAt, &sch.NextFireAt, &sch.CreatedAt, &sch.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Schedule{}, ErrNotFound
	}
	return sch, err
}

// DeleteSchedule removes the schedule row.
func (s *Store) DeleteSchedule(ctx context.Context, orgID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM schedule WHERE org_id = $1`, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimDueSchedules atomically grabs every enabled schedule whose next_fire_at
// has elapsed, advances next_fire_at to the supplied newNext (per-row), and
// returns the claimed rows so the caller can enqueue runs. The SELECT ...
// FOR UPDATE SKIP LOCKED clause means concurrent scheduler workers (across
// instances) never claim the same row twice.
//
// nextFn is a callback that returns the next fire time for a given expression
// — typically a cron-library `Next(now)` call. Rows whose nextFn errors out
// are returned with NextFireAt unchanged so the caller can log + skip.
func (s *Store) ClaimDueSchedules(ctx context.Context, now time.Time, nextFn func(expr string) (time.Time, error)) ([]Schedule, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit path returns nil

	rows, err := tx.Query(ctx,
		`SELECT id, org_id, cron_expr, enabled, last_fired_at, next_fire_at, created_at, updated_at
		 FROM schedule
		 WHERE enabled AND next_fire_at <= $1
		 ORDER BY next_fire_at
		 FOR UPDATE SKIP LOCKED`, now)
	if err != nil {
		return nil, err
	}
	var claimed []Schedule
	for rows.Next() {
		var sch Schedule
		if err := rows.Scan(&sch.ID, &sch.OrgID, &sch.CronExpr, &sch.Enabled,
			&sch.LastFiredAt, &sch.NextFireAt, &sch.CreatedAt, &sch.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		claimed = append(claimed, sch)
	}
	rows.Close()

	for i := range claimed {
		next, err := nextFn(claimed[i].CronExpr)
		if err != nil {
			// Bad expression: bump next_fire_at by 1h so we don't busy-loop
			// claiming the same broken row every scheduler tick.
			next = now.Add(time.Hour)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE schedule SET last_fired_at = $2, next_fire_at = $3, updated_at = now()
			 WHERE id = $1`, claimed[i].ID, now, next); err != nil {
			return nil, err
		}
		claimed[i].LastFiredAt = &now
		claimed[i].NextFireAt = next
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return claimed, nil
}

// ─── Runs ───────────────────────────────────────────────────────────────

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
	TriggeredByUser   *uuid.UUID `json:"triggered_by_user,omitempty"`
}

// CreateRunParams identifies who triggered the run. Exactly one of TokenID
// or UserID may be non-nil; passing both is allowed but only the token
// attribution is shown in audit views by convention.
type CreateRunParams struct {
	OrgID   uuid.UUID
	TokenID *uuid.UUID
	UserID  *uuid.UUID
}

// CreateRun inserts a new run in pending state.
func (s *Store) CreateRun(ctx context.Context, p CreateRunParams) (Run, error) {
	r := Run{OrgID: p.OrgID, Status: RunPending,
		TriggeredByToken: p.TokenID, TriggeredByUser: p.UserID}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO run(org_id, status, triggered_by_token, triggered_by_user)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, started_at`,
		p.OrgID, string(r.Status), p.TokenID, p.UserID,
	).Scan(&r.ID, &r.StartedAt)
	return r, err
}

// MarkRunRunning transitions pending → running.
func (s *Store) MarkRunRunning(ctx context.Context, runID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE run SET status = 'running' WHERE id = $1`, runID)
	return err
}

// CompleteRun marks the run as succeeded and stores summary + findings JSON.
func (s *Store) CompleteRun(ctx context.Context, runID uuid.UUID, summary, findings []byte) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE run SET status = 'succeeded', completed_at = now(),
		 summary = $2, findings = $3 WHERE id = $1`,
		runID, summary, findings)
	return err
}

// FailRun marks the run as failed with an error message.
func (s *Store) FailRun(ctx context.Context, runID uuid.UUID, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE run SET status = 'failed', completed_at = now(), error_message = $2
		 WHERE id = $1`, runID, errMsg)
	return err
}

// GetRun fetches a run by ID, scoped to orgID.
func (s *Store) GetRun(ctx context.Context, orgID, runID uuid.UUID) (Run, error) {
	var r Run
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, status, started_at, completed_at,
		        COALESCE(error_message,''), summary, findings,
		        triggered_by_token, triggered_by_user
		 FROM run WHERE id = $1 AND org_id = $2`,
		runID, orgID,
	).Scan(&r.ID, &r.OrgID, &r.Status, &r.StartedAt, &r.CompletedAt,
		&r.ErrorMessage, &r.Summary, &r.Findings,
		&r.TriggeredByToken, &r.TriggeredByUser)
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
		`SELECT id, org_id, status, started_at, completed_at, COALESCE(error_message,''),
		        triggered_by_token, triggered_by_user
		 FROM run WHERE org_id = $1 ORDER BY started_at DESC LIMIT $2`,
		orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Status, &r.StartedAt,
			&r.CompletedAt, &r.ErrorMessage,
			&r.TriggeredByToken, &r.TriggeredByUser); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
