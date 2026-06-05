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

type WebhookDeliveryStatus string

const (
	DeliveryDelivering WebhookDeliveryStatus = "delivering"
	DeliverySucceeded  WebhookDeliveryStatus = "succeeded"
	DeliveryFailed     WebhookDeliveryStatus = "failed"
	DeliveryDead       WebhookDeliveryStatus = "dead"
)

type WebhookDelivery struct {
	ID              uuid.UUID
	WebhookID       uuid.UUID
	EventID         uuid.UUID
	OrgID           uuid.UUID
	EventKind       string
	Status          WebhookDeliveryStatus
	AttemptCount    int
	LastHTTPStatus  int
	LastError       string
	AttemptsLog     []byte // raw JSONB array
	CreatedAt       time.Time
	LastAttemptedAt *time.Time
	NextAttemptAt   *time.Time
	SucceededAt     *time.Time
	AbandonedAt     *time.Time

	WebhookURL    string
	WebhookSecret string
}

type AttemptResult struct {
	AttemptedAt time.Time `json:"attempted_at"`
	HTTPStatus  int       `json:"http_status"`
	Error       string    `json:"error,omitempty"`
	DurationMS  int64     `json:"duration_ms"`
}

type UpsertDeliveryParams struct {
	WebhookID uuid.UUID
	EventID   uuid.UUID
	OrgID     uuid.UUID
	EventKind string
}

func (s *Store) UpsertDelivery(ctx context.Context, p UpsertDeliveryParams) (uuid.UUID, bool, error) {
	var id uuid.UUID
	var inserted bool
	err := s.pool.QueryRow(ctx,
		`INSERT INTO webhook_delivery
		    (webhook_id, event_id, org_id, event_kind, status)
		 VALUES ($1, $2, $3, $4, 'delivering')
		 ON CONFLICT (webhook_id, event_id) DO UPDATE
		    SET event_kind = EXCLUDED.event_kind  -- no-op write, just so RETURNING returns the row
		 RETURNING id, (xmax = 0) AS inserted`,
		p.WebhookID, p.EventID, p.OrgID, p.EventKind,
	).Scan(&id, &inserted)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("store: upsert delivery: %w", err)
	}
	return id, inserted, nil
}

func (s *Store) MarkDeliverySucceeded(ctx context.Context, id uuid.UUID, result AttemptResult) error {
	entry, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("store: marshal attempt: %w", err)
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE webhook_delivery
		 SET status            = 'succeeded',
		     attempt_count     = attempt_count + 1,
		     last_http_status  = $2,
		     last_error        = NULL,
		     last_attempted_at = $3,
		     succeeded_at      = $3,
		     next_attempt_at   = NULL,
		     attempts_log      = attempts_log || $4::jsonb
		 WHERE id = $1`,
		id, result.HTTPStatus, result.AttemptedAt, entry)
	return err
}

func (s *Store) MarkDeliveryFailed(ctx context.Context, id uuid.UUID, result AttemptResult, backoff time.Duration, maxAttempts int) (WebhookDeliveryStatus, error) {
	entry, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("store: marshal attempt: %w", err)
	}
	var status string
	err = s.pool.QueryRow(ctx,
		`UPDATE webhook_delivery
		 SET attempt_count    = attempt_count + 1,
		     last_http_status = $2,
		     last_error       = $3,
		     last_attempted_at = $4,
		     attempts_log     = attempts_log || $5::jsonb,
		     status = CASE
		                WHEN attempt_count + 1 >= $7 THEN 'dead'
		                ELSE 'failed'
		              END,
		     next_attempt_at = CASE
		                         WHEN attempt_count + 1 >= $7 THEN NULL
		                         ELSE now() + ($6::bigint * interval '1 microsecond')
		                       END
		 WHERE id = $1
		 RETURNING status`,
		id, result.HTTPStatus, result.Error, result.AttemptedAt, entry,
		backoff.Microseconds(), maxAttempts,
	).Scan(&status)
	if err != nil {
		return "", fmt.Errorf("store: mark delivery failed: %w", err)
	}
	return WebhookDeliveryStatus(status), nil
}

func (s *Store) ClaimPendingDeliveries(ctx context.Context, limit int) (pgx.Tx, []WebhookDelivery, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("store: begin claim deliveries: %w", err)
	}
	rows, err := tx.Query(ctx,
		`SELECT d.id, d.webhook_id, d.event_id, d.org_id, d.event_kind,
		        d.status, d.attempt_count, d.last_http_status,
		        COALESCE(d.last_error,''), d.attempts_log,
		        d.created_at, d.last_attempted_at, d.next_attempt_at,
		        d.succeeded_at, d.abandoned_at,
		        w.url, w.secret
		 FROM webhook_delivery d
		 JOIN webhook w ON w.id = d.webhook_id AND w.enabled
		 WHERE d.status = 'failed'
		   AND d.abandoned_at IS NULL
		   AND d.next_attempt_at <= now()
		 ORDER BY d.next_attempt_at, d.created_at
		 LIMIT $1
		 FOR UPDATE OF d SKIP LOCKED`,
		limit,
	)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, nil, fmt.Errorf("store: claim pending: %w", err)
	}
	defer rows.Close()

	var out []WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventID, &d.OrgID, &d.EventKind,
			&d.Status, &d.AttemptCount, &d.LastHTTPStatus, &d.LastError, &d.AttemptsLog,
			&d.CreatedAt, &d.LastAttemptedAt, &d.NextAttemptAt, &d.SucceededAt, &d.AbandonedAt,
			&d.WebhookURL, &d.WebhookSecret); err != nil {
			_ = tx.Rollback(ctx)
			return nil, nil, fmt.Errorf("store: scan pending: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		_ = tx.Rollback(ctx)
		return nil, nil, fmt.Errorf("store: iterate pending: %w", err)
	}
	return tx, out, nil
}

func (s *Store) MarkDeliverySucceededTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, result AttemptResult) error {
	entry, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("store: marshal attempt: %w", err)
	}
	_, err = tx.Exec(ctx,
		`UPDATE webhook_delivery
		 SET status            = 'succeeded',
		     attempt_count     = attempt_count + 1,
		     last_http_status  = $2,
		     last_error        = NULL,
		     last_attempted_at = $3,
		     succeeded_at      = $3,
		     next_attempt_at   = NULL,
		     attempts_log      = attempts_log || $4::jsonb
		 WHERE id = $1`,
		id, result.HTTPStatus, result.AttemptedAt, entry)
	return err
}

func (s *Store) MarkDeliveryFailedTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, result AttemptResult, backoff time.Duration, maxAttempts int) (WebhookDeliveryStatus, error) {
	entry, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("store: marshal attempt: %w", err)
	}
	var status string
	err = tx.QueryRow(ctx,
		`UPDATE webhook_delivery
		 SET attempt_count    = attempt_count + 1,
		     last_http_status = $2,
		     last_error       = $3,
		     last_attempted_at = $4,
		     attempts_log     = attempts_log || $5::jsonb,
		     status = CASE
		                WHEN attempt_count + 1 >= $7 THEN 'dead'
		                ELSE 'failed'
		              END,
		     next_attempt_at = CASE
		                         WHEN attempt_count + 1 >= $7 THEN NULL
		                         ELSE now() + ($6::bigint * interval '1 microsecond')
		                       END
		 WHERE id = $1
		 RETURNING status`,
		id, result.HTTPStatus, result.Error, result.AttemptedAt, entry,
		backoff.Microseconds(), maxAttempts,
	).Scan(&status)
	if err != nil {
		return "", fmt.Errorf("store: mark failed (tx): %w", err)
	}
	return WebhookDeliveryStatus(status), nil
}

func (s *Store) GetWebhookDelivery(ctx context.Context, id uuid.UUID) (WebhookDelivery, error) {
	var d WebhookDelivery
	err := s.pool.QueryRow(ctx,
		`SELECT id, webhook_id, event_id, org_id, event_kind, status,
		        attempt_count, last_http_status, COALESCE(last_error,''),
		        attempts_log, created_at, last_attempted_at, next_attempt_at,
		        succeeded_at, abandoned_at
		 FROM webhook_delivery WHERE id = $1`, id,
	).Scan(&d.ID, &d.WebhookID, &d.EventID, &d.OrgID, &d.EventKind, &d.Status,
		&d.AttemptCount, &d.LastHTTPStatus, &d.LastError,
		&d.AttemptsLog, &d.CreatedAt, &d.LastAttemptedAt, &d.NextAttemptAt,
		&d.SucceededAt, &d.AbandonedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return WebhookDelivery{}, ErrNotFound
	}
	return d, err
}

type ListDeadDeliveriesFilters struct {
	OrgID  *uuid.UUID
	Kind   string
	Limit  int
	Offset int
}

func (s *Store) ListDeadDeliveries(ctx context.Context, f ListDeadDeliveriesFilters) ([]WebhookDelivery, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	q := `SELECT id, webhook_id, event_id, org_id, event_kind, status,
	             attempt_count, last_http_status, COALESCE(last_error,''),
	             attempts_log, created_at, last_attempted_at, next_attempt_at,
	             succeeded_at, abandoned_at
	      FROM webhook_delivery
	      WHERE status = 'dead' AND abandoned_at IS NULL`
	args := []any{}
	if f.OrgID != nil {
		q += " AND org_id = $" + intToArg(len(args)+1)
		args = append(args, *f.OrgID)
	}
	if f.Kind != "" {
		q += " AND event_kind = $" + intToArg(len(args)+1)
		args = append(args, f.Kind)
	}
	q += " ORDER BY created_at DESC LIMIT $" + intToArg(len(args)+1) +
		" OFFSET $" + intToArg(len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventID, &d.OrgID, &d.EventKind, &d.Status,
			&d.AttemptCount, &d.LastHTTPStatus, &d.LastError,
			&d.AttemptsLog, &d.CreatedAt, &d.LastAttemptedAt, &d.NextAttemptAt,
			&d.SucceededAt, &d.AbandonedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) ReplayDelivery(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE webhook_delivery
		 SET status          = 'failed',
		     attempt_count   = 0,
		     last_error      = NULL,
		     next_attempt_at = now(),
		     abandoned_at    = NULL
		 WHERE id = $1 AND status IN ('dead','failed')`,
		id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AbandonDelivery(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE webhook_delivery
		 SET abandoned_at = now()
		 WHERE id = $1 AND status IN ('dead','failed','delivering')
		   AND abandoned_at IS NULL`,
		id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

