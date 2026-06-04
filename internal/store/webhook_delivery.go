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

// WebhookDeliveryStatus is the row-level state machine. Only four values
// are valid; any other in the DB is a bug.
type WebhookDeliveryStatus string

const (
	DeliveryDelivering WebhookDeliveryStatus = "delivering"
	DeliverySucceeded  WebhookDeliveryStatus = "succeeded"
	DeliveryFailed     WebhookDeliveryStatus = "failed"
	DeliveryDead       WebhookDeliveryStatus = "dead"
)

// WebhookDelivery is one (webhook, event) pair the worker is responsible
// for. Re-fired event_ids land on the same row (UNIQUE constraint) so
// the consumer's INSERT becomes a safe UPSERT.
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

	// WebhookURL + WebhookSecret are populated by ClaimPendingDeliveries
	// and ClaimFirstAttempts so the caller can POST without an extra
	// query per row. They are NOT columns on webhook_delivery — they
	// come from the webhook table via the FK join.
	WebhookURL    string
	WebhookSecret string
}

// AttemptResult is the per-attempt forensic record appended to
// attempts_log. Keep the field set small — operators read these on a
// dashboard.
type AttemptResult struct {
	AttemptedAt time.Time `json:"attempted_at"`
	HTTPStatus  int       `json:"http_status"`
	Error       string    `json:"error,omitempty"`
	DurationMS  int64     `json:"duration_ms"`
}

// UpsertDeliveryParams seeds a new row (or no-ops if a row with the
// same (webhook_id, event_id) already exists). Returns the row id.
// Used by the Kafka consumer right before it POSTs the first attempt.
type UpsertDeliveryParams struct {
	WebhookID uuid.UUID
	EventID   uuid.UUID
	OrgID     uuid.UUID
	EventKind string
}

// UpsertDelivery either INSERTs a new row in 'delivering' state, or — if
// the unique key collides — leaves the existing row alone and returns
// its id. Returns (id, created bool, error). created=false means the row
// already existed; the caller should treat that as "this event has
// already been processed for this webhook" and skip.
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

// MarkDeliverySucceeded records a successful attempt and transitions
// status to 'succeeded'. The attempt result is appended to attempts_log.
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

// MarkDeliveryFailed records a failed attempt. If the new attempt_count
// reaches maxAttempts, status becomes 'dead' (no more retries);
// otherwise 'failed' with next_attempt_at = now() + backoff.
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

// ClaimPendingDeliveries is the Retrier hot path: claim up to limit
// failed rows whose backoff window has elapsed, locking them with
// SELECT FOR UPDATE SKIP LOCKED so concurrent workers shard the work.
//
// The returned tx must be committed (success) or rolled back by the
// caller. Rows are joined with `webhook` so the caller has the URL +
// secret without a second query per row. The query filters out
// disabled or deleted webhooks via the INNER JOIN.
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
		        d.succeeded_at,
		        w.url, w.secret
		 FROM webhook_delivery d
		 JOIN webhook w ON w.id = d.webhook_id AND w.enabled
		 WHERE d.status = 'failed' AND d.next_attempt_at <= now()
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
			&d.CreatedAt, &d.LastAttemptedAt, &d.NextAttemptAt, &d.SucceededAt,
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

// MarkDeliverySucceededTx is the tx-scoped sibling of
// MarkDeliverySucceeded — used inside ClaimPendingDeliveries' tx so
// state transitions don't race the lock.
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

// MarkDeliveryFailedTx is the tx-scoped sibling of MarkDeliveryFailed.
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

// GetWebhookDelivery fetches one delivery by id. ErrNotFound when no
// such row exists. Used by operator endpoints.
func (s *Store) GetWebhookDelivery(ctx context.Context, id uuid.UUID) (WebhookDelivery, error) {
	var d WebhookDelivery
	err := s.pool.QueryRow(ctx,
		`SELECT id, webhook_id, event_id, org_id, event_kind, status,
		        attempt_count, last_http_status, COALESCE(last_error,''),
		        attempts_log, created_at, last_attempted_at, next_attempt_at,
		        succeeded_at
		 FROM webhook_delivery WHERE id = $1`, id,
	).Scan(&d.ID, &d.WebhookID, &d.EventID, &d.OrgID, &d.EventKind, &d.Status,
		&d.AttemptCount, &d.LastHTTPStatus, &d.LastError,
		&d.AttemptsLog, &d.CreatedAt, &d.LastAttemptedAt, &d.NextAttemptAt,
		&d.SucceededAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return WebhookDelivery{}, ErrNotFound
	}
	return d, err
}

