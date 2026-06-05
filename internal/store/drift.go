package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type DriftEvent struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	RunID      uuid.UUID  `json:"run_id"`
	PriorRunID *uuid.UUID `json:"prior_run_id,omitempty"`
	ControlID  string     `json:"control_id"`
	From       string     `json:"from"`
	To         string     `json:"to"`
	Rationale  string     `json:"rationale,omitempty"`
	OccurredAt time.Time  `json:"occurred_at"`
}

type RecordDriftEventParams struct {
	OrgID      uuid.UUID
	RunID      uuid.UUID
	PriorRunID *uuid.UUID
	ControlID  string
	From       string
	To         string
	Rationale  string
}

func (s *Store) RecordDriftEvents(ctx context.Context, events []RecordDriftEventParams) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck — rollback after commit is a no-op

	for _, e := range events {
		if _, err := tx.Exec(ctx,
			`INSERT INTO drift_event
			   (org_id, run_id, prior_run_id, control_id,
			    from_status, to_status, rationale)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			e.OrgID, e.RunID, e.PriorRunID, e.ControlID,
			e.From, e.To, nullIfEmpty(e.Rationale),
		); err != nil {
			return fmt.Errorf("inserting drift event for control %q: %w",
				e.ControlID, err)
		}
	}
	return tx.Commit(ctx)
}

type ListDriftOptions struct {
	Since     time.Time
	Until     time.Time
	ControlID string
	From      string // exact-match filter on from_status
	To        string // exact-match filter on to_status
	Limit     int
}

func (s *Store) ListDriftEvents(ctx context.Context, orgID uuid.UUID, opts ListDriftOptions) ([]DriftEvent, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 500 {
		opts.Limit = 500
	}
	q := `SELECT id, org_id, run_id, prior_run_id, control_id,
	             from_status, to_status, COALESCE(rationale,''), occurred_at
	      FROM drift_event WHERE org_id = $1`
	args := []any{orgID}
	if !opts.Since.IsZero() {
		args = append(args, opts.Since)
		q += fmt.Sprintf(" AND occurred_at >= $%d", len(args))
	}
	if !opts.Until.IsZero() {
		args = append(args, opts.Until)
		q += fmt.Sprintf(" AND occurred_at < $%d", len(args))
	}
	if opts.ControlID != "" {
		args = append(args, opts.ControlID)
		q += fmt.Sprintf(" AND control_id = $%d", len(args))
	}
	if opts.From != "" {
		args = append(args, opts.From)
		q += fmt.Sprintf(" AND from_status = $%d", len(args))
	}
	if opts.To != "" {
		args = append(args, opts.To)
		q += fmt.Sprintf(" AND to_status = $%d", len(args))
	}
	args = append(args, opts.Limit)
	q += fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DriftEvent
	for rows.Next() {
		var e DriftEvent
		if err := rows.Scan(&e.ID, &e.OrgID, &e.RunID, &e.PriorRunID,
			&e.ControlID, &e.From, &e.To, &e.Rationale, &e.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ListDriftEventsForRun(ctx context.Context, orgID, runID uuid.UUID) ([]DriftEvent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, run_id, prior_run_id, control_id,
		        from_status, to_status, COALESCE(rationale,''), occurred_at
		 FROM drift_event
		 WHERE org_id = $1 AND run_id = $2
		 ORDER BY occurred_at DESC`,
		orgID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DriftEvent
	for rows.Next() {
		var e DriftEvent
		if err := rows.Scan(&e.ID, &e.OrgID, &e.RunID, &e.PriorRunID,
			&e.ControlID, &e.From, &e.To, &e.Rationale, &e.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

