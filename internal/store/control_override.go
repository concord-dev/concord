package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ControlOverride struct {
	ID        uuid.UUID `json:"id"`
	OrgID     uuid.UUID `json:"org_id"`
	ControlID string    `json:"control_id"`
	Params    []byte    `json:"params"` // raw JSON
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

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
