package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Organization is one customer organization.
type Organization struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateOrganization inserts an org and returns it. Slug must be unique.
func (s *Store) CreateOrganization(ctx context.Context, name, slug string) (Organization, error) {
	var o Organization
	err := s.pool.QueryRow(ctx,
		`INSERT INTO organization(name, slug) VALUES ($1, $2)
		 RETURNING id, name, slug, created_at, updated_at`,
		name, slug,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return Organization{}, fmt.Errorf("inserting organization: %w", err)
	}
	return o, nil
}

// GetOrganizationBySlug looks up an org by its human-readable slug.
func (s *Store) GetOrganizationBySlug(ctx context.Context, slug string) (Organization, error) {
	var o Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, created_at, updated_at FROM organization WHERE slug = $1`, slug,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}

// GetOrganizationByID looks up an org by ID.
func (s *Store) GetOrganizationByID(ctx context.Context, id uuid.UUID) (Organization, error) {
	var o Organization
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, created_at, updated_at FROM organization WHERE id = $1`, id,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}

// ListOrganizations returns every organization, oldest first.
func (s *Store) ListOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, slug, created_at, updated_at FROM organization ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
