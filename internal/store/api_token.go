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
