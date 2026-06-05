package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type RunStatus string

const (
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
)

type RunSource string

const (
	RunSourceAgent RunSource = "agent"
)

type Run struct {
	ID               uuid.UUID  `json:"id"`
	OrgID            uuid.UUID  `json:"org_id"`
	Status           RunStatus  `json:"status"`
	Source           RunSource  `json:"source"`
	StartedAt        time.Time  `json:"started_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	ErrorMessage     string     `json:"error_message,omitempty"`
	Summary          []byte     `json:"summary,omitempty"`  // raw JSON
	Findings         []byte     `json:"findings,omitempty"` // raw JSON
	TriggeredByToken *uuid.UUID `json:"triggered_by_token,omitempty"`
	TriggeredByUser  *uuid.UUID `json:"triggered_by_user,omitempty"`
	AgentVersion     string     `json:"agent_version,omitempty"`
}

type SubmitRunParams struct {
	OrgID        uuid.UUID
	TokenID      *uuid.UUID
	UserID       *uuid.UUID
	AgentVersion string
	Source       RunSource // must be RunSourceAgent
	StartedAt    time.Time
	CompletedAt  time.Time
	Summary      []byte
	Findings     []byte
}

func (s *Store) SubmitRun(ctx context.Context, p SubmitRunParams) (Run, error) {
	if p.Source != RunSourceAgent {
		return Run{}, errors.New("SubmitRun requires Source = RunSourceAgent")
	}
	r := Run{
		OrgID:            p.OrgID,
		Status:           RunSucceeded,
		Source:           p.Source,
		StartedAt:        p.StartedAt,
		CompletedAt:      &p.CompletedAt,
		Summary:          p.Summary,
		Findings:         p.Findings,
		TriggeredByToken: p.TokenID,
		TriggeredByUser:  p.UserID,
		AgentVersion:     p.AgentVersion,
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO run(org_id, status, source, started_at, completed_at,
		                 summary, findings,
		                 triggered_by_token, triggered_by_user,
		                 agent_version)
		 VALUES ($1, 'succeeded', $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id`,
		p.OrgID, string(p.Source), p.StartedAt, p.CompletedAt,
		p.Summary, p.Findings,
		p.TokenID, p.UserID,
		nullIfEmpty(p.AgentVersion),
	).Scan(&r.ID)
	return r, err
}

func (s *Store) GetRun(ctx context.Context, orgID, runID uuid.UUID) (Run, error) {
	var r Run
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, status, source, started_at, completed_at,
		        COALESCE(error_message,''), summary, findings,
		        triggered_by_token, triggered_by_user,
		        COALESCE(agent_version,'')
		 FROM run WHERE id = $1 AND org_id = $2`,
		runID, orgID,
	).Scan(&r.ID, &r.OrgID, &r.Status, &r.Source, &r.StartedAt, &r.CompletedAt,
		&r.ErrorMessage, &r.Summary, &r.Findings,
		&r.TriggeredByToken, &r.TriggeredByUser,
		&r.AgentVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	return r, err
}

func (s *Store) ListRuns(ctx context.Context, orgID uuid.UUID, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, status, source, started_at, completed_at, COALESCE(error_message,''),
		        triggered_by_token, triggered_by_user,
		        COALESCE(agent_version,'')
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
			&r.AgentVersion); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetLatestSucceededRun(ctx context.Context, orgID uuid.UUID) (Run, error) {
	var r Run
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, status, source, started_at, completed_at,
		        COALESCE(error_message,''), summary, findings,
		        triggered_by_token, triggered_by_user,
		        COALESCE(agent_version,'')
		 FROM run
		 WHERE org_id = $1 AND status = 'succeeded'
		 ORDER BY started_at DESC
		 LIMIT 1`,
		orgID,
	).Scan(&r.ID, &r.OrgID, &r.Status, &r.Source, &r.StartedAt, &r.CompletedAt,
		&r.ErrorMessage, &r.Summary, &r.Findings,
		&r.TriggeredByToken, &r.TriggeredByUser,
		&r.AgentVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	return r, err
}

func (s *Store) GetPreviousRunFindings(ctx context.Context, orgID, excludeRunID uuid.UUID) ([]byte, uuid.UUID, error) {
	var (
		priorID  uuid.UUID
		findings []byte
	)
	err := s.pool.QueryRow(ctx,
		`SELECT id, findings
		 FROM run
		 WHERE org_id = $1 AND id <> $2
		 ORDER BY started_at DESC
		 LIMIT 1`,
		orgID, excludeRunID,
	).Scan(&priorID, &findings)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, uuid.Nil, ErrNotFound
	}
	return findings, priorID, err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
