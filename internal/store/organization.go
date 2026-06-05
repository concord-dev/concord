package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Organization struct {
	ID                 uuid.UUID `json:"id"`
	Name               string    `json:"name"`
	Slug               string    `json:"slug"`
	TrustPortalEnabled bool      `json:"trust_portal_enabled"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

const orgColumns = "id, name, slug, trust_portal_enabled, created_at, updated_at"

func scanOrg(row pgx.Row, o *Organization) error {
	return row.Scan(&o.ID, &o.Name, &o.Slug, &o.TrustPortalEnabled, &o.CreatedAt, &o.UpdatedAt)
}

func (s *Store) CreateOrganization(ctx context.Context, name, slug string) (Organization, error) {
	var o Organization
	err := scanOrg(s.pool.QueryRow(ctx,
		`INSERT INTO organization(name, slug) VALUES ($1, $2)
		 RETURNING `+orgColumns,
		name, slug,
	), &o)
	if err != nil {
		return Organization{}, fmt.Errorf("inserting organization: %w", err)
	}
	return o, nil
}

func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (Organization, error) {
	var o Organization
	err := scanOrg(s.pool.QueryRow(ctx,
		`SELECT `+orgColumns+` FROM organization WHERE slug = $1`, slug,
	), &o)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}

func (s *Store) GetOrganizationByID(ctx context.Context, id uuid.UUID) (Organization, error) {
	var o Organization
	err := scanOrg(s.pool.QueryRow(ctx,
		`SELECT `+orgColumns+` FROM organization WHERE id = $1`, id,
	), &o)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}

func (s *Store) ListOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+orgColumns+` FROM organization ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		var o Organization
		if err := scanOrg(rows, &o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) SetTrustPortalEnabled(ctx context.Context, orgID uuid.UUID, enabled bool) (Organization, error) {
	var o Organization
	err := scanOrg(s.pool.QueryRow(ctx,
		`UPDATE organization SET trust_portal_enabled = $1, updated_at = NOW()
		 WHERE id = $2
		 RETURNING `+orgColumns,
		enabled, orgID,
	), &o)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}
