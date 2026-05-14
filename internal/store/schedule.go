package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Schedule is one cron-driven trigger for an organization's compliance runs.
// Exactly one row per org (UNIQUE enforces it); set enabled=false to pause
// without losing the cron expression.
type Schedule struct {
	ID          uuid.UUID  `json:"id"`
	OrgID       uuid.UUID  `json:"org_id"`
	CronExpr    string     `json:"cron_expr"`
	Enabled     bool       `json:"enabled"`
	LastFiredAt *time.Time `json:"last_fired_at,omitempty"`
	NextFireAt  time.Time  `json:"next_fire_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// UpsertSchedule replaces (or creates) the schedule row for an org. The
// caller is responsible for computing nextFireAt from the cron expression —
// the store layer does not know about cron parsing.
func (s *Store) UpsertSchedule(ctx context.Context, orgID uuid.UUID, cronExpr string, enabled bool, nextFireAt time.Time) (Schedule, error) {
	if cronExpr == "" {
		return Schedule{}, errors.New("cron_expr is required")
	}
	var sch Schedule
	err := s.pool.QueryRow(ctx,
		`INSERT INTO schedule(org_id, cron_expr, enabled, next_fire_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (org_id) DO UPDATE SET
		   cron_expr = EXCLUDED.cron_expr,
		   enabled = EXCLUDED.enabled,
		   next_fire_at = EXCLUDED.next_fire_at,
		   updated_at = now()
		 RETURNING id, org_id, cron_expr, enabled, last_fired_at, next_fire_at, created_at, updated_at`,
		orgID, cronExpr, enabled, nextFireAt,
	).Scan(&sch.ID, &sch.OrgID, &sch.CronExpr, &sch.Enabled,
		&sch.LastFiredAt, &sch.NextFireAt, &sch.CreatedAt, &sch.UpdatedAt)
	if err != nil {
		return Schedule{}, fmt.Errorf("upserting schedule: %w", err)
	}
	return sch, nil
}

// GetSchedule returns the schedule for orgID, or ErrNotFound.
func (s *Store) GetSchedule(ctx context.Context, orgID uuid.UUID) (Schedule, error) {
	var sch Schedule
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, cron_expr, enabled, last_fired_at, next_fire_at, created_at, updated_at
		 FROM schedule WHERE org_id = $1`, orgID,
	).Scan(&sch.ID, &sch.OrgID, &sch.CronExpr, &sch.Enabled,
		&sch.LastFiredAt, &sch.NextFireAt, &sch.CreatedAt, &sch.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Schedule{}, ErrNotFound
	}
	return sch, err
}

// DeleteSchedule removes the schedule row.
func (s *Store) DeleteSchedule(ctx context.Context, orgID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM schedule WHERE org_id = $1`, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimDueSchedules atomically grabs every enabled schedule whose next_fire_at
// has elapsed, advances next_fire_at to the supplied newNext (per-row), and
// returns the claimed rows so the caller can enqueue runs. The SELECT ...
// FOR UPDATE SKIP LOCKED clause means concurrent scheduler workers (across
// instances) never claim the same row twice.
//
// nextFn is a callback that returns the next fire time for a given expression
// — typically a cron-library `Next(now)` call. Rows whose nextFn errors out
// get bumped +1h to avoid busy-looping on a broken row.
func (s *Store) ClaimDueSchedules(ctx context.Context, now time.Time, nextFn func(expr string) (time.Time, error)) ([]Schedule, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit path returns nil

	rows, err := tx.Query(ctx,
		`SELECT id, org_id, cron_expr, enabled, last_fired_at, next_fire_at, created_at, updated_at
		 FROM schedule
		 WHERE enabled AND next_fire_at <= $1
		 ORDER BY next_fire_at
		 FOR UPDATE SKIP LOCKED`, now)
	if err != nil {
		return nil, err
	}
	var claimed []Schedule
	for rows.Next() {
		var sch Schedule
		if err := rows.Scan(&sch.ID, &sch.OrgID, &sch.CronExpr, &sch.Enabled,
			&sch.LastFiredAt, &sch.NextFireAt, &sch.CreatedAt, &sch.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		claimed = append(claimed, sch)
	}
	rows.Close()

	for i := range claimed {
		next, err := nextFn(claimed[i].CronExpr)
		if err != nil {
			next = now.Add(time.Hour)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE schedule SET last_fired_at = $2, next_fire_at = $3, updated_at = now()
			 WHERE id = $1`, claimed[i].ID, now, next); err != nil {
			return nil, err
		}
		claimed[i].LastFiredAt = &now
		claimed[i].NextFireAt = next
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return claimed, nil
}
