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

// PasswordReset is a single live-or-spent reset record. The plaintext token
// is never persisted; only its sha256 lands in token_hash.
type PasswordReset struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	ExpiresAt   time.Time  `json:"expires_at"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
	RequesterIP string     `json:"requester_ip,omitempty"`
	RequesterUA string     `json:"requester_ua,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// CreatePasswordResetParams carries the inputs from the request handler so
// audit metadata gets stamped at creation time (rather than fetched later).
type CreatePasswordResetParams struct {
	UserID      uuid.UUID
	TTL         time.Duration // defaults to 1h
	RequesterIP string
	RequesterUA string
}

// CreatePasswordReset mints a fresh token and stores its hash. Returns the
// plaintext (callers deliver it out-of-band) + the row. Multiple outstanding
// resets per user are allowed by design: a user who hits "forgot password"
// twice should be able to use either email's link until one of them is
// consumed or expires.
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

// ConsumePasswordResetParams holds the token + the new password for the
// confirm step. The full update runs in one transaction so a crash mid-flow
// leaves no partially-applied state (e.g. password updated but sessions still
// alive, or used_at set but password unchanged).
type ConsumePasswordResetParams struct {
	Token       string
	NewPassword string
}

// ConsumePasswordReset validates the token and atomically:
//  1. updates the user's password_hash to the argon2id of NewPassword
//  2. marks this reset row used
//  3. revokes every active session for the user
//
// API tokens are intentionally left alone — CI/automation creds shouldn't
// break because a human reset their UI password. Returns the user (so the
// handler can issue a fresh session if it wants to auto-login).
//
// Error semantics:
//   - Unknown token: ErrNotFound
//   - Expired token: ErrPasswordResetExpired (distinct so handlers can 410)
//   - Already used: ErrNotFound (collapsed — re-submission must not be a
//     replay oracle for "did this token ever exist?")
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

	// SELECT FOR UPDATE prevents two concurrent confirms from both winning.
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
	// Revoke every active session for the user — same effect as a manual
	// "log out everywhere" after a credential change.
	if _, err := tx.Exec(ctx,
		`UPDATE user_session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
		pr.UserID,
	); err != nil {
		return User{}, fmt.Errorf("revoking sessions: %w", err)
	}

	// Re-read the user so the caller sees post-update timestamps.
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

// ErrPasswordResetExpired distinguishes an expired token from an unknown one
// so handlers can show "this link expired, ask for a new one" without
// confirming that a token ever existed for some other input.
var ErrPasswordResetExpired = errors.New("password reset expired")
