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

type Webhook struct {
	ID          uuid.UUID  `json:"id"`
	OrgID       uuid.UUID  `json:"org_id"`
	URL         string     `json:"url"`
	Secret      string     `json:"secret,omitempty"` // omitted from list/get for safety
	EventKinds  []string   `json:"event_kinds"`
	Enabled     bool       `json:"enabled"`
	LastFiredAt *time.Time `json:"last_fired_at,omitempty"`
	LastStatus  *int       `json:"last_status,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type CreateWebhookParams struct {
	OrgID      uuid.UUID
	URL        string
	Secret     string
	EventKinds []string
	Enabled    bool
}

type UpdateWebhookParams struct {
	URL        *string
	EventKinds *[]string
	Enabled    *bool
}

func (s *Store) CreateWebhook(ctx context.Context, p CreateWebhookParams) (Webhook, string, error) {
	if p.URL == "" {
		return Webhook{}, "", errors.New("url is required")
	}
	if p.Secret == "" {
		secret, err := auth.GenerateSecret("whsec_", 24)
		if err != nil {
			return Webhook{}, "", err
		}
		p.Secret = secret
	}
	kinds := p.EventKinds
	if kinds == nil {
		kinds = []string{}
	}
	var wh Webhook
	err := s.pool.QueryRow(ctx,
		`INSERT INTO webhook(org_id, url, secret, event_kinds, enabled)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, org_id, url, secret, event_kinds, enabled,
		           last_fired_at, last_status, COALESCE(last_error,''), created_at, updated_at`,
		p.OrgID, p.URL, p.Secret, kinds, p.Enabled,
	).Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Secret, &wh.EventKinds, &wh.Enabled,
		&wh.LastFiredAt, &wh.LastStatus, &wh.LastError, &wh.CreatedAt, &wh.UpdatedAt)
	if err != nil {
		return Webhook{}, "", fmt.Errorf("inserting webhook: %w", err)
	}
	return wh, p.Secret, nil
}

func (s *Store) GetWebhook(ctx context.Context, orgID, id uuid.UUID) (Webhook, error) {
	var wh Webhook
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, url, secret, event_kinds, enabled,
		        last_fired_at, last_status, COALESCE(last_error,''), created_at, updated_at
		 FROM webhook WHERE id = $1 AND org_id = $2`,
		id, orgID,
	).Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Secret, &wh.EventKinds, &wh.Enabled,
		&wh.LastFiredAt, &wh.LastStatus, &wh.LastError, &wh.CreatedAt, &wh.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Webhook{}, ErrNotFound
	}
	return wh, err
}

func (s *Store) ListWebhooks(ctx context.Context, orgID uuid.UUID) ([]Webhook, error) {
	return s.queryWebhooks(ctx,
		`SELECT id, org_id, url, secret, event_kinds, enabled,
		        last_fired_at, last_status, COALESCE(last_error,''), created_at, updated_at
		 FROM webhook WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
}

func (s *Store) ListEnabledWebhooks(ctx context.Context, orgID uuid.UUID) ([]Webhook, error) {
	return s.queryWebhooks(ctx,
		`SELECT id, org_id, url, secret, event_kinds, enabled,
		        last_fired_at, last_status, COALESCE(last_error,''), created_at, updated_at
		 FROM webhook WHERE org_id = $1 AND enabled = true`, orgID)
}

func (s *Store) queryWebhooks(ctx context.Context, sql string, orgID uuid.UUID) ([]Webhook, error) {
	rows, err := s.pool.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		var wh Webhook
		if err := rows.Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Secret, &wh.EventKinds, &wh.Enabled,
			&wh.LastFiredAt, &wh.LastStatus, &wh.LastError, &wh.CreatedAt, &wh.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, wh)
	}
	return out, rows.Err()
}

func (s *Store) UpdateWebhook(ctx context.Context, orgID, id uuid.UUID, p UpdateWebhookParams) (Webhook, error) {
	current, err := s.GetWebhook(ctx, orgID, id)
	if err != nil {
		return Webhook{}, err
	}
	if p.URL != nil {
		current.URL = *p.URL
	}
	if p.EventKinds != nil {
		current.EventKinds = *p.EventKinds
	}
	if p.Enabled != nil {
		current.Enabled = *p.Enabled
	}
	var wh Webhook
	err = s.pool.QueryRow(ctx,
		`UPDATE webhook SET url = $3, event_kinds = $4, enabled = $5, updated_at = now()
		 WHERE id = $1 AND org_id = $2
		 RETURNING id, org_id, url, secret, event_kinds, enabled,
		           last_fired_at, last_status, COALESCE(last_error,''), created_at, updated_at`,
		id, orgID, current.URL, current.EventKinds, current.Enabled,
	).Scan(&wh.ID, &wh.OrgID, &wh.URL, &wh.Secret, &wh.EventKinds, &wh.Enabled,
		&wh.LastFiredAt, &wh.LastStatus, &wh.LastError, &wh.CreatedAt, &wh.UpdatedAt)
	return wh, err
}

func (s *Store) DeleteWebhook(ctx context.Context, orgID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM webhook WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RecordWebhookResult(ctx context.Context, id uuid.UUID, status int, errMsg string) error {
	var errPtr *string
	if errMsg != "" {
		errPtr = &errMsg
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE webhook SET last_fired_at = now(), last_status = $2, last_error = $3, updated_at = now()
		 WHERE id = $1`, id, status, errPtr)
	return err
}
