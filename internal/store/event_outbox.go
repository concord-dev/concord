package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type EventOutboxRow struct {
	ID             uuid.UUID  `json:"id"`
	EventID        uuid.UUID  `json:"event_id"`
	OrgID          uuid.UUID  `json:"org_id"`
	Kind           string     `json:"kind"`
	Payload        []byte     `json:"payload"`
	Traceparent    *string    `json:"traceparent,omitempty"`
	OccurredAt     time.Time  `json:"occurred_at"`
	CreatedAt      time.Time  `json:"created_at"`
	PublishedAt    *time.Time `json:"published_at,omitempty"`
	AttemptCount   int        `json:"attempt_count"`
	LastError      *string    `json:"last_error,omitempty"`
	NextAttemptAt  time.Time  `json:"next_attempt_at"`
	AbandonedAt    *time.Time `json:"abandoned_at,omitempty"`
}

type ListDeadOutboxFilters struct {
	OrgID   *uuid.UUID
	Kind    string
	Limit   int
	Offset  int
}

func (s *Store) ListDeadOutbox(ctx context.Context, maxAttempts int, f ListDeadOutboxFilters) ([]EventOutboxRow, error) {
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

	q := `SELECT id, event_id, org_id, kind, payload, traceparent,
	             occurred_at, created_at, published_at, attempt_count,
	             last_error, next_attempt_at, abandoned_at
	      FROM event_outbox
	      WHERE published_at IS NULL
	        AND abandoned_at IS NULL
	        AND attempt_count >= $1`
	args := []any{maxAttempts}
	if f.OrgID != nil {
		q += " AND org_id = $" + intToArg(len(args)+1)
		args = append(args, *f.OrgID)
	}
	if f.Kind != "" {
		q += " AND kind = $" + intToArg(len(args)+1)
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

	var out []EventOutboxRow
	for rows.Next() {
		var r EventOutboxRow
		if err := rows.Scan(&r.ID, &r.EventID, &r.OrgID, &r.Kind, &r.Payload, &r.Traceparent,
			&r.OccurredAt, &r.CreatedAt, &r.PublishedAt, &r.AttemptCount,
			&r.LastError, &r.NextAttemptAt, &r.AbandonedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetOutboxRow(ctx context.Context, id uuid.UUID) (EventOutboxRow, error) {
	var r EventOutboxRow
	err := s.pool.QueryRow(ctx,
		`SELECT id, event_id, org_id, kind, payload, traceparent,
		        occurred_at, created_at, published_at, attempt_count,
		        last_error, next_attempt_at, abandoned_at
		 FROM event_outbox WHERE id = $1`, id,
	).Scan(&r.ID, &r.EventID, &r.OrgID, &r.Kind, &r.Payload, &r.Traceparent,
		&r.OccurredAt, &r.CreatedAt, &r.PublishedAt, &r.AttemptCount,
		&r.LastError, &r.NextAttemptAt, &r.AbandonedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return EventOutboxRow{}, ErrNotFound
	}
	return r, err
}

func (s *Store) ReplayOutbox(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE event_outbox
		 SET attempt_count   = 0,
		     last_error      = NULL,
		     next_attempt_at = now(),
		     abandoned_at    = NULL
		 WHERE id = $1 AND published_at IS NULL`,
		id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AbandonOutbox(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE event_outbox
		 SET abandoned_at = now()
		 WHERE id = $1 AND published_at IS NULL AND abandoned_at IS NULL`,
		id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func intToArg(n int) string {
	if n < 10 {
		return string('0' + byte(n))
	}
	const digits = "0123456789"
	if n < 100 {
		return string([]byte{digits[n/10], digits[n%10]})
	}
	return string([]byte{digits[n/100], digits[(n/10)%10], digits[n%10]})
}
