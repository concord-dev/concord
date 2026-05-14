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
