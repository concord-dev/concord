package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/concord-dev/concord/internal/auth"
)


var ErrMFAAlreadyEnrolled = errors.New("mfa: user already has an enrolled TOTP secret")

var ErrMFANotEnrolled = errors.New("mfa: user has no enrolled TOTP secret")

var ErrMFAChallengeExpired = errors.New("mfa: challenge expired")


type UserTOTP struct {
	UserID     uuid.UUID  `json:"user_id"`
	Secret     string     `json:"-"`
	EnrolledAt *time.Time `json:"enrolled_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type MFAChallenge struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}


func (s *Store) BeginUserTOTPEnrollment(ctx context.Context, userID uuid.UUID, base32Secret string) error {
	var enrolledAt *time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT enrolled_at FROM user_totp WHERE user_id = $1`, userID,
	).Scan(&enrolledAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		_, err = s.pool.Exec(ctx,
			`INSERT INTO user_totp (user_id, secret) VALUES ($1, $2)`,
			userID, base32Secret)
		return err
	case err != nil:
		return err
	}
	if enrolledAt != nil {
		return ErrMFAAlreadyEnrolled
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE user_totp SET secret = $2 WHERE user_id = $1`,
		userID, base32Secret)
	return err
}

func (s *Store) GetUserTOTP(ctx context.Context, userID uuid.UUID) (UserTOTP, error) {
	var t UserTOTP
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, secret, enrolled_at, last_used_at, created_at
		 FROM user_totp WHERE user_id = $1`, userID,
	).Scan(&t.UserID, &t.Secret, &t.EnrolledAt, &t.LastUsedAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserTOTP{}, ErrNotFound
	}
	return t, err
}

func (s *Store) MarkUserTOTPEnrolled(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE user_totp SET enrolled_at = now() WHERE user_id = $1 AND enrolled_at IS NULL`,
		userID)
	return err
}

func (s *Store) MarkUserTOTPUsed(ctx context.Context, userID uuid.UUID) {
	_, _ = s.pool.Exec(ctx,
		`UPDATE user_totp SET last_used_at = now() WHERE user_id = $1`, userID)
}

func (s *Store) IsUserMFAEnrolled(ctx context.Context, userID uuid.UUID) (bool, error) {
	var enrolledAt *time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT enrolled_at FROM user_totp WHERE user_id = $1`, userID,
	).Scan(&enrolledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return enrolledAt != nil, nil
}

func (s *Store) DisableUserMFA(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck — rollback after commit is a no-op

	if _, err := tx.Exec(ctx, `DELETE FROM user_totp WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_code WHERE user_id = $1`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}


func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, plaintextCodes []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_code WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, code := range plaintextCodes {
		h, err := auth.HashPassword(normalizeRecoveryCode(code))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_recovery_code (user_id, code_hash) VALUES ($1, $2)`,
			userID, h); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_recovery_code
		 WHERE user_id = $1 AND used_at IS NULL`, userID,
	).Scan(&n)
	return n, err
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID uuid.UUID, plaintext string) (bool, error) {
	plaintext = normalizeRecoveryCode(plaintext)
	rows, err := s.pool.Query(ctx,
		`SELECT id, code_hash FROM user_recovery_code
		 WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		return false, err
	}
	type row struct {
		id   uuid.UUID
		hash string
	}
	var candidates []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.hash); err != nil {
			rows.Close()
			return false, err
		}
		candidates = append(candidates, r)
	}
	rows.Close()

	for _, c := range candidates {
		ok, err := auth.VerifyPassword(plaintext, c.hash)
		if err != nil {
			return false, err
		}
		if ok {
			_, err := s.pool.Exec(ctx,
				`UPDATE user_recovery_code SET used_at = now() WHERE id = $1 AND used_at IS NULL`,
				c.id)
			return err == nil, err
		}
	}
	return false, nil
}

func normalizeRecoveryCode(s string) string {
	r := strings.NewReplacer("-", "", " ", "")
	return strings.ToLower(r.Replace(s))
}


func (s *Store) CreateMFAChallenge(ctx context.Context, userID uuid.UUID, ip, ua string, ttl time.Duration) (MFAChallenge, string, error) {
	plain, err := auth.GenerateSecret(auth.MFAChallengePrefix, 32)
	if err != nil {
		return MFAChallenge{}, "", err
	}
	sum := sha256.Sum256([]byte(plain))
	expires := time.Now().UTC().Add(ttl)
	var ch MFAChallenge
	err = s.pool.QueryRow(ctx,
		`INSERT INTO mfa_challenge (user_id, token_hash, ip, user_agent, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, expires_at, consumed_at, created_at`,
		userID, sum[:], nullIfEmpty(ip), nullIfEmpty(ua), expires,
	).Scan(&ch.ID, &ch.UserID, &ch.ExpiresAt, &ch.ConsumedAt, &ch.CreatedAt)
	if err != nil {
		return MFAChallenge{}, "", err
	}
	return ch, plain, nil
}

func (s *Store) ConsumeMFAChallenge(ctx context.Context, plaintext string) (uuid.UUID, error) {
	sum := sha256.Sum256([]byte(plaintext))

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var (
		id        uuid.UUID
		userID    uuid.UUID
		expiresAt time.Time
	)
	err = tx.QueryRow(ctx,
		`SELECT id, user_id, expires_at
		 FROM mfa_challenge
		 WHERE token_hash = $1 AND consumed_at IS NULL
		 FOR UPDATE`,
		sum[:],
	).Scan(&id, &userID, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	if time.Now().UTC().After(expiresAt) {
		return uuid.Nil, ErrMFAChallengeExpired
	}
	if _, err := tx.Exec(ctx,
		`UPDATE mfa_challenge SET consumed_at = now() WHERE id = $1`, id,
	); err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}
