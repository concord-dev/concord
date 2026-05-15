package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RunStatus enumerates the terminal states an agent-submitted run can carry.
// `succeeded` is what every successful POST /v1/orgs/{slug}/runs writes;
// `failed` is reserved for agents that want to report a hard error from
// their own collectors. The legacy `pending` / `running` states from the
// server-side worker era are gone — runs land terminal.
type RunStatus string

const (
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
)

// RunSource describes how a run row got into the table. Single value today
// (`agent`) — the field is kept to make future provenance (e.g. operator
// uploads, federated runs) a zero-migration addition.
type RunSource string

const (
	RunSourceAgent RunSource = "agent"
)

// Run is the row shape for one evaluation cycle.
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

// SubmitRunParams carries an agent-completed run for direct insertion.
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

// SubmitRun inserts a completed run from an agent push. Unlike CreateRun,
// this is a single-shot insert: no pending → running transition.
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

// GetRun fetches a run by ID, scoped to orgID.
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

// ListRuns returns the last `limit` runs for an organization, newest first.
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

// nullIfEmpty converts an empty string to a nil interface so pgx writes SQL NULL.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
