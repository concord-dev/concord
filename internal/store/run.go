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

// RunSource describes how a run row got into the table.
//
//	server   — the in-process worker ran it (legacy path; operator-only now)
//	agent    — an agent pushed a completed run with a verified Ed25519 signature
//	unsigned — an agent pushed but didn't sign (API token auth alone)
type RunSource string

const (
	RunSourceServer   RunSource = "server"
	RunSourceAgent    RunSource = "agent"
	RunSourceUnsigned RunSource = "unsigned"
)

// Run is the row shape for one evaluation cycle.
type Run struct {
	ID                 uuid.UUID  `json:"id"`
	OrgID              uuid.UUID  `json:"org_id"`
	Status             RunStatus  `json:"status"`
	Source             RunSource  `json:"source"`
	StartedAt          time.Time  `json:"started_at"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
	ErrorMessage       string     `json:"error_message,omitempty"`
	Summary            []byte     `json:"summary,omitempty"`  // raw JSON
	Findings           []byte     `json:"findings,omitempty"` // raw JSON
	TriggeredByToken   *uuid.UUID `json:"triggered_by_token,omitempty"`
	TriggeredByUser    *uuid.UUID `json:"triggered_by_user,omitempty"`
	AgentID            *uuid.UUID `json:"agent_id,omitempty"`
	AgentVersion       string     `json:"agent_version,omitempty"`
	SignatureVerified  bool       `json:"signature_verified"`
}

// CreateRunParams identifies who triggered the run. Exactly one of TokenID
// or UserID may be non-nil; passing both is allowed but only the token
// attribution is shown in audit views by convention.
type CreateRunParams struct {
	OrgID   uuid.UUID
	TokenID *uuid.UUID
	UserID  *uuid.UUID
}

// CreateRun inserts a new run in pending state (server-side worker path).
func (s *Store) CreateRun(ctx context.Context, p CreateRunParams) (Run, error) {
	r := Run{OrgID: p.OrgID, Status: RunPending, Source: RunSourceServer,
		TriggeredByToken: p.TokenID, TriggeredByUser: p.UserID}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO run(org_id, status, source, triggered_by_token, triggered_by_user)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, started_at`,
		p.OrgID, string(r.Status), string(r.Source), p.TokenID, p.UserID,
	).Scan(&r.ID, &r.StartedAt)
	return r, err
}

// SubmitRunParams carries an agent-completed run for direct insertion. The
// run lands as 'succeeded' immediately — the agent has already done the work.
type SubmitRunParams struct {
	OrgID             uuid.UUID
	TokenID           *uuid.UUID
	UserID            *uuid.UUID
	AgentID           *uuid.UUID // set when the push was Ed25519-signed
	AgentVersion      string
	Source            RunSource // RunSourceAgent or RunSourceUnsigned
	SignatureVerified bool
	StartedAt         time.Time // agent-reported timestamps
	CompletedAt       time.Time
	Summary           []byte
	Findings          []byte
}

// SubmitRun inserts a completed run from an agent push. Unlike CreateRun,
// this is a single-shot insert: no pending → running transition.
func (s *Store) SubmitRun(ctx context.Context, p SubmitRunParams) (Run, error) {
	if p.Source != RunSourceAgent && p.Source != RunSourceUnsigned {
		return Run{}, errors.New("SubmitRun requires Source = RunSourceAgent or RunSourceUnsigned")
	}
	r := Run{
		OrgID:             p.OrgID,
		Status:            RunSucceeded,
		Source:            p.Source,
		StartedAt:         p.StartedAt,
		CompletedAt:       &p.CompletedAt,
		Summary:           p.Summary,
		Findings:          p.Findings,
		TriggeredByToken:  p.TokenID,
		TriggeredByUser:   p.UserID,
		AgentID:           p.AgentID,
		AgentVersion:      p.AgentVersion,
		SignatureVerified: p.SignatureVerified,
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO run(org_id, status, source, started_at, completed_at,
		                 summary, findings,
		                 triggered_by_token, triggered_by_user,
		                 agent_id, agent_version, signature_verified)
		 VALUES ($1, 'succeeded', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 RETURNING id`,
		p.OrgID, string(p.Source), p.StartedAt, p.CompletedAt,
		p.Summary, p.Findings,
		p.TokenID, p.UserID,
		p.AgentID, nullIfEmpty(p.AgentVersion), p.SignatureVerified,
	).Scan(&r.ID)
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
		`SELECT id, org_id, status, source, started_at, completed_at,
		        COALESCE(error_message,''), summary, findings,
		        triggered_by_token, triggered_by_user,
		        agent_id, COALESCE(agent_version,''), signature_verified
		 FROM run WHERE id = $1 AND org_id = $2`,
		runID, orgID,
	).Scan(&r.ID, &r.OrgID, &r.Status, &r.Source, &r.StartedAt, &r.CompletedAt,
		&r.ErrorMessage, &r.Summary, &r.Findings,
		&r.TriggeredByToken, &r.TriggeredByUser,
		&r.AgentID, &r.AgentVersion, &r.SignatureVerified)
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
		`SELECT id, org_id, status, source, started_at, completed_at, COALESCE(error_message,''),
		        triggered_by_token, triggered_by_user,
		        agent_id, COALESCE(agent_version,''), signature_verified
		 FROM run WHERE org_id = $1 ORDER BY started_at DESC LIMIT $2`,
		orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Status, &r.Source, &r.StartedAt,
			&r.CompletedAt, &r.ErrorMessage,
			&r.TriggeredByToken, &r.TriggeredByUser,
			&r.AgentID, &r.AgentVersion, &r.SignatureVerified); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// nullIfEmpty converts an empty string to a nil interface so pgx writes SQL NULL.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
