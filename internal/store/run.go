package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RunStatus enumerates the lifecycle states a run moves through.
type RunStatus string

const (
	RunPending   RunStatus = "pending"
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
)

// Run is the row shape for one evaluation cycle.
type Run struct {
	ID               uuid.UUID  `json:"id"`
	OrgID            uuid.UUID  `json:"org_id"`
	Status           RunStatus  `json:"status"`
	StartedAt        time.Time  `json:"started_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	ErrorMessage     string     `json:"error_message,omitempty"`
	Summary          []byte     `json:"summary,omitempty"`  // raw JSON
	Findings         []byte     `json:"findings,omitempty"` // raw JSON
	TriggeredByToken *uuid.UUID `json:"triggered_by_token,omitempty"`
	TriggeredByUser  *uuid.UUID `json:"triggered_by_user,omitempty"`
}

// CreateRunParams identifies who triggered the run. Exactly one of TokenID
// or UserID may be non-nil; passing both is allowed but only the token
// attribution is shown in audit views by convention.
type CreateRunParams struct {
	OrgID   uuid.UUID
	TokenID *uuid.UUID
	UserID  *uuid.UUID
}

// CreateRun inserts a new run in pending state.
func (s *Store) CreateRun(ctx context.Context, p CreateRunParams) (Run, error) {
	r := Run{OrgID: p.OrgID, Status: RunPending,
		TriggeredByToken: p.TokenID, TriggeredByUser: p.UserID}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO run(org_id, status, triggered_by_token, triggered_by_user)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, started_at`,
		p.OrgID, string(r.Status), p.TokenID, p.UserID,
	).Scan(&r.ID, &r.StartedAt)
	return r, err
}

// MarkRunRunning transitions pending → running.
func (s *Store) MarkRunRunning(ctx context.Context, runID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE run SET status = 'running' WHERE id = $1`, runID)
	return err
}

// CompleteRun marks the run as succeeded and stores summary + findings JSON.
func (s *Store) CompleteRun(ctx context.Context, runID uuid.UUID, summary, findings []byte) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE run SET status = 'succeeded', completed_at = now(),
		 summary = $2, findings = $3 WHERE id = $1`,
		runID, summary, findings)
	return err
}

// FailRun marks the run as failed with an error message.
func (s *Store) FailRun(ctx context.Context, runID uuid.UUID, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE run SET status = 'failed', completed_at = now(), error_message = $2
		 WHERE id = $1`, runID, errMsg)
	return err
}

// GetRun fetches a run by ID, scoped to orgID.
func (s *Store) GetRun(ctx context.Context, orgID, runID uuid.UUID) (Run, error) {
	var r Run
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, status, started_at, completed_at,
		        COALESCE(error_message,''), summary, findings,
		        triggered_by_token, triggered_by_user
		 FROM run WHERE id = $1 AND org_id = $2`,
		runID, orgID,
	).Scan(&r.ID, &r.OrgID, &r.Status, &r.StartedAt, &r.CompletedAt,
		&r.ErrorMessage, &r.Summary, &r.Findings,
		&r.TriggeredByToken, &r.TriggeredByUser)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	return r, err
}

// ListRuns returns the last `limit` runs for an organization, newest first.
func (s *Store) ListRuns(ctx context.Context, orgID uuid.UUID, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, status, started_at, completed_at, COALESCE(error_message,''),
		        triggered_by_token, triggered_by_user
		 FROM run WHERE org_id = $1 ORDER BY started_at DESC LIMIT $2`,
		orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Status, &r.StartedAt,
			&r.CompletedAt, &r.ErrorMessage,
			&r.TriggeredByToken, &r.TriggeredByUser); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
