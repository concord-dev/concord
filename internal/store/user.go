package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/concord-dev/concord/internal/auth"
)

// User is one human principal. Email + password drive web login; users
// without a password_hash are invite-pending or SSO-only.
//
// IsAuditor is the cross-org read flag. When true, HasPermission grants
// every `*:read` permission on every organization regardless of
// user_org_role membership — the model for external compliance auditors
// who need broad read access without per-tenant onboarding. Grants are
// operator-only (CONCORD_OPERATOR_TOKEN); see SetUserAuditor.
type User struct {
	ID              uuid.UUID  `json:"id"`
	FirstName       string     `json:"first_name"`
	LastName        string     `json:"last_name"`
	Email           string     `json:"email"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	IsAuditor       bool       `json:"is_auditor"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// userColumns is the canonical SELECT projection for User. Single source of
// truth so a new column lands everywhere at once.
const userColumns = `id, first_name, last_name, email, email_verified_at, is_auditor, created_at, updated_at`

// userScanArgs returns the pointer slice matching userColumns, in order.
// Pass to pgx.Row.Scan / pgx.Rows.Scan with `Scan(userScanArgs(&u)...)`.
func userScanArgs(u *User) []any {
	return []any{&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.EmailVerifiedAt, &u.IsAuditor, &u.CreatedAt, &u.UpdatedAt}
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
		 RETURNING `+userColumns,
		p.FirstName, p.LastName, p.Email, pwHash,
	).Scan(userScanArgs(&u)...)
	if err != nil {
		return User{}, fmt.Errorf("inserting user: %w", err)
	}
	return u, nil
}

// GetUserByID looks up a user by ID.
func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM "user" WHERE id = $1`, id,
	).Scan(userScanArgs(&u)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// GetUserByEmail performs a case-insensitive email lookup.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM "user" WHERE lower(email) = lower($1)`, email,
	).Scan(userScanArgs(&u)...)
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
	dest := append(userScanArgs(&u), &hash)
	err := s.pool.QueryRow(ctx,
		`SELECT `+userColumns+`, password_hash
		 FROM "user" WHERE lower(email) = lower($1)`, email,
	).Scan(dest...)
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
		`SELECT `+userColumns+` FROM "user" ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(userScanArgs(&u)...); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserAuditor toggles the cross-org read flag for an external auditor.
// Idempotent — re-setting the same value is fine. Returns ErrNotFound when
// no user matches. The caller is responsible for revoking the user's
// active sessions (or not) per their threat model; this method only
// touches the flag.
func (s *Store) SetUserAuditor(ctx context.Context, userID uuid.UUID, isAuditor bool) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE "user" SET is_auditor = $1, updated_at = now() WHERE id = $2`,
		isAuditor, userID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// IsUserAuditor returns whether the named user holds the cross-org read
// flag. Hot path — called from RequireOrgPerm for every read-permission
// check on a session caller, so the lookup is a single indexed read.
func (s *Store) IsUserAuditor(ctx context.Context, userID uuid.UUID) (bool, error) {
	var is bool
	err := s.pool.QueryRow(ctx,
		`SELECT is_auditor FROM "user" WHERE id = $1`, userID,
	).Scan(&is)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	return is, err
}

// ListAuditors returns every user with the cross-org read flag set.
// Powers the operator dashboard's "who can read everything" page.
func (s *Store) ListAuditors(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+userColumns+` FROM "user" WHERE is_auditor ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(userScanArgs(&u)...); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
