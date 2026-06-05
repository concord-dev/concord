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

const userColumns = `id, first_name, last_name, email, email_verified_at, is_auditor, created_at, updated_at`

func userScanArgs(u *User) []any {
	return []any{&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.EmailVerifiedAt, &u.IsAuditor, &u.CreatedAt, &u.UpdatedAt}
}

type CreateUserParams struct {
	FirstName string
	LastName  string
	Email     string
	Password  string // optional
}

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
