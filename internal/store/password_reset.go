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

type PasswordReset struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	ExpiresAt   time.Time  `json:"expires_at"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
	RequesterIP string     `json:"requester_ip,omitempty"`
	RequesterUA string     `json:"requester_ua,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type CreatePasswordResetParams struct {
	UserID      uuid.UUID
	TTL         time.Duration // defaults to 1h
	RequesterIP string
	RequesterUA string
}

func (s *Store) CreatePasswordReset(ctx context.Context, p CreatePasswordResetParams) (PasswordReset, string, error) {
	if p.TTL <= 0 {
		p.TTL = time.Hour
	}
	plain, err := auth.GenerateSecret(auth.PasswordResetPrefix, 32)
	if err != nil {
		return PasswordReset{}, "", err
	}
	hashBytes, err := hexToBytes(auth.HashSecret(plain))
	if err != nil {
		return PasswordReset{}, "", err
	}
	var pr PasswordReset
	err = s.pool.QueryRow(ctx,
		`INSERT INTO password_reset(user_id, token_hash, expires_at, requester_ip, requester_ua)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, expires_at, used_at,
		           COALESCE(requester_ip,''), COALESCE(requester_ua,''), created_at`,
		p.UserID, hashBytes, time.Now().Add(p.TTL),
		nullIfEmpty(p.RequesterIP), nullIfEmpty(p.RequesterUA),
	).Scan(&pr.ID, &pr.UserID, &pr.ExpiresAt, &pr.UsedAt,
		&pr.RequesterIP, &pr.RequesterUA, &pr.CreatedAt)
	if err != nil {
		return PasswordReset{}, "", fmt.Errorf("inserting password reset: %w", err)
	}
	return pr, plain, nil
}

type ConsumePasswordResetParams struct {
	Token       string
	NewPassword string
}

func (s *Store) ConsumePasswordReset(ctx context.Context, p ConsumePasswordResetParams) (User, error) {
	if p.NewPassword == "" {
		return User{}, errors.New("new_password is required")
	}
	hashBytes, err := hexToBytes(auth.HashSecret(p.Token))
	if err != nil {
		return User{}, err
	}
	newHash, err := auth.HashPassword(p.NewPassword)
	if err != nil {
		return User{}, fmt.Errorf("hashing new password: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var pr PasswordReset
	err = tx.QueryRow(ctx,
		`SELECT id, user_id, expires_at, used_at FROM password_reset
		 WHERE token_hash = $1 AND used_at IS NULL
		 FOR UPDATE`,
		hashBytes,
	).Scan(&pr.ID, &pr.UserID, &pr.ExpiresAt, &pr.UsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	if time.Now().After(pr.ExpiresAt) {
		return User{}, ErrPasswordResetExpired
	}

	if _, err := tx.Exec(ctx,
		`UPDATE "user" SET password_hash = $1, updated_at = now() WHERE id = $2`,
		newHash, pr.UserID,
	); err != nil {
		return User{}, fmt.Errorf("updating password: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE password_reset SET used_at = now() WHERE id = $1`, pr.ID,
	); err != nil {
		return User{}, fmt.Errorf("marking reset used: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE user_session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
		pr.UserID,
	); err != nil {
		return User{}, fmt.Errorf("revoking sessions: %w", err)
	}

	var u User
	if err := tx.QueryRow(ctx,
		`SELECT `+userColumns+` FROM "user" WHERE id = $1`, pr.UserID,
	).Scan(userScanArgs(&u)...); err != nil {
		return User{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}
	return u, nil
}

var ErrPasswordResetExpired = errors.New("password reset expired")
