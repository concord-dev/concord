package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AgentKey is a registered Ed25519 public key an agent uses to sign pushes.
// PublicKey is the raw 32-byte key; base64 encoding is a wire concern only.
type AgentKey struct {
	ID              uuid.UUID  `json:"id"`
	OrgID           uuid.UUID  `json:"org_id"`
	Name            string     `json:"name"`
	PublicKey       []byte     `json:"public_key"`
	CreatedByUserID *uuid.UUID `json:"created_by_user_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

const agentKeyColumns = "id, org_id, name, public_key, created_by_user_id, created_at, last_used_at, revoked_at"

func scanAgentKey(row pgx.Row, k *AgentKey) error {
	return row.Scan(&k.ID, &k.OrgID, &k.Name, &k.PublicKey,
		&k.CreatedByUserID, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
}

// CreateAgentKey registers a new public key for an org. publicKey must be the
// raw 32-byte Ed25519 public key; callers (handlers) are responsible for
// decoding the base64 wire form before calling.
func (s *Store) CreateAgentKey(ctx context.Context, orgID uuid.UUID, name string, publicKey []byte, createdBy *uuid.UUID) (AgentKey, error) {
	if len(publicKey) != 32 {
		return AgentKey{}, errors.New("public key must be exactly 32 bytes (Ed25519)")
	}
	var k AgentKey
	err := scanAgentKey(s.pool.QueryRow(ctx,
		`INSERT INTO agent_key(org_id, name, public_key, created_by_user_id)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+agentKeyColumns,
		orgID, name, publicKey, createdBy,
	), &k)
	return k, err
}

// ListAgentKeys returns active (non-revoked) keys for an org, oldest first.
func (s *Store) ListAgentKeys(ctx context.Context, orgID uuid.UUID) ([]AgentKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+agentKeyColumns+` FROM agent_key
		 WHERE org_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at ASC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentKey
	for rows.Next() {
		var k AgentKey
		if err := scanAgentKey(rows, &k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// GetAgentKey returns a single active key by ID, scoped to orgID. Returns
// ErrNotFound when missing or revoked — handlers must not distinguish the two
// cases in error messages so a revoked-key push isn't a replay oracle.
func (s *Store) GetAgentKey(ctx context.Context, orgID, keyID uuid.UUID) (AgentKey, error) {
	var k AgentKey
	err := scanAgentKey(s.pool.QueryRow(ctx,
		`SELECT `+agentKeyColumns+` FROM agent_key
		 WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`,
		keyID, orgID,
	), &k)
	if errors.Is(err, pgx.ErrNoRows) {
		return AgentKey{}, ErrNotFound
	}
	return k, err
}

// RevokeAgentKey soft-deletes a key. Past runs that referenced it keep their
// agent_id pointer (because the FK is ON DELETE SET NULL — but we never
// hard-delete keys, so the link stays intact for audit).
func (s *Store) RevokeAgentKey(ctx context.Context, orgID, keyID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE agent_key SET revoked_at = now()
		 WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`,
		keyID, orgID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkAgentKeyUsed bumps last_used_at to now. Best-effort; failures don't
// block a verified push from succeeding.
func (s *Store) MarkAgentKeyUsed(ctx context.Context, keyID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE agent_key SET last_used_at = now() WHERE id = $1`, keyID)
	return err
}
