package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EventOutboxRow is the operator-facing view of one event_outbox row.
// Distinct from internal/eventbus's outboxRow (which is the dispatcher's
// claim shape) so the operator surface can evolve independently — for
// example, adding org_name via a JOIN without touching the dispatcher.
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

// ListDeadOutboxFilters narrows the dead-letter list. Zero values are
// "no filter" — Limit defaults to 50, capped at 500.
type ListDeadOutboxFilters struct {
	OrgID   *uuid.UUID
	Kind    string
	Limit   int
	Offset  int
}

// ListDeadOutbox returns the most-recent un-published, non-abandoned
// rows that have reached the dispatcher's max-attempts ceiling. The
// dispatcher won't touch these any more — an operator's the only path
// forward.
//
// Caller passes the same MaxAttempts value the dispatcher uses so the
// filter matches the dispatcher's "this row is dead" definition; today
// that's hard-coded to 20 in both places but exposing it here keeps
// us honest if cmd/server's flag ever changes.
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

	// Build query dynamically so the per-filter EXPLAIN stays clean.
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

// GetOutboxRow fetches one row by id. Returns ErrNotFound when the row
// doesn't exist.
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

// ReplayOutbox makes a dead row eligible for the dispatcher again:
// attempt_count resets to 0, last_error clears, next_attempt_at jumps
// to now(), and abandoned_at clears (so a previously-abandoned row can
// be revived). Returns ErrNotFound when the row doesn't exist.
//
// The reset is unconditional — operator is explicitly choosing to
// re-try. If the row was already 'succeeded' (published_at NOT NULL),
// the UPDATE is a no-op so this can't accidentally re-fire something
// that was already delivered.
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

// AbandonOutbox marks a dead row as "operator gave up". The dispatcher
// skips abandoned rows (its claim query has AND abandoned_at IS NULL).
// Forensic columns (attempts_log analog: attempt_count + last_error +
// payload) stay intact for compliance queries.
//
// Returns ErrNotFound when the row doesn't exist or has already
// been published.
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

// intToArg is the smallest possible itoa for placeholder-building. We
// keep it private to this file so the rest of the package isn't
// tempted to use it instead of fmt.Sprintf.
func intToArg(n int) string {
	if n < 10 {
		return string('0' + byte(n))
	}
	// Caller-side limit makes this branch unreachable in practice
	// (we never accumulate more than 10 placeholders), but stay
	// defensive so a future filter doesn't silently corrupt the query.
	const digits = "0123456789"
	if n < 100 {
		return string([]byte{digits[n/10], digits[n%10]})
	}
	return string([]byte{digits[n/100], digits[(n/10)%10], digits[n%10]})
}
