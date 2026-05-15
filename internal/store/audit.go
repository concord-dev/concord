package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// AuditActor enumerates the principal kinds that can be recorded as the
// `actor_kind` of an audit_event row. The string values match the CHECK
// constraint in 0001_init.up.sql — don't rename without a migration.
type AuditActor string

const (
	AuditActorUser            AuditActor = "user"
	AuditActorToken           AuditActor = "token"
	AuditActorOperator        AuditActor = "operator"
	AuditActorUnauthenticated AuditActor = "unauthenticated"
	AuditActorSystem          AuditActor = "system"
)

// AuditEvent is the read shape returned by ListAuditEvents.
type AuditEvent struct {
	ID           uuid.UUID       `json:"id"`
	OccurredAt   time.Time       `json:"occurred_at"`
	ActorKind    AuditActor      `json:"actor_kind"`
	ActorUserID  *uuid.UUID      `json:"actor_user_id,omitempty"`
	ActorTokenID *uuid.UUID      `json:"actor_token_id,omitempty"`
	OrgID        *uuid.UUID      `json:"org_id,omitempty"`
	Action       string          `json:"action"`
	TargetType   string          `json:"target_type,omitempty"`
	TargetID     *uuid.UUID      `json:"target_id,omitempty"`
	IP           string          `json:"ip,omitempty"`
	UserAgent    string          `json:"user_agent,omitempty"`
	RequestID    string          `json:"request_id,omitempty"`
	Details      json.RawMessage `json:"details,omitempty"`
}

// RecordAuditParams is the write surface. Zero values are tolerated for every
// optional field; ActorKind and Action are the only hard requirements.
type RecordAuditParams struct {
	ActorKind    AuditActor
	ActorUserID  *uuid.UUID
	ActorTokenID *uuid.UUID
	OrgID        *uuid.UUID
	Action       string
	TargetType   string
	TargetID     *uuid.UUID
	IP           string
	UserAgent    string
	RequestID    string
	Details      map[string]any
}

// RecordAudit inserts one audit event. Failures are logged but never returned
// — auditing is best-effort and must NEVER fail the request that triggered
// it. Calling code can rely on this being a noisy slog.Error on disaster
// without having to handle errors at every call site.
func (s *Store) RecordAudit(ctx context.Context, p RecordAuditParams) {
	if p.ActorKind == "" || p.Action == "" {
		slog.Error("audit: missing required fields",
			slog.String("actor_kind", string(p.ActorKind)),
			slog.String("action", p.Action))
		return
	}
	var details []byte
	if len(p.Details) > 0 {
		b, err := json.Marshal(p.Details)
		if err != nil {
			slog.Error("audit: marshal details failed",
				slog.String("action", p.Action),
				slog.String("err", err.Error()))
			b = []byte(`{}`)
		}
		details = b
	} else {
		details = []byte(`{}`)
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_event (
		     actor_kind, actor_user_id, actor_token_id, org_id,
		     action, target_type, target_id,
		     ip, user_agent, request_id, details
		 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		string(p.ActorKind), p.ActorUserID, p.ActorTokenID, p.OrgID,
		p.Action, nullIfEmpty(p.TargetType), p.TargetID,
		nullIfEmpty(p.IP), nullIfEmpty(p.UserAgent), nullIfEmpty(p.RequestID),
		details,
	)
	if err != nil {
		slog.Error("audit: insert failed",
			slog.String("action", p.Action),
			slog.String("err", err.Error()))
	}
}

// ListAuditOptions configures ListAuditEvents. Zero values mean "no filter"
// except Limit which defaults to 50 and is capped at 500 server-side so a
// hostile caller can't request a million-row scan.
type ListAuditOptions struct {
	Since  time.Time
	Until  time.Time
	Action string
	Limit  int
}

// ListAuditEvents returns audit rows for an org, newest first. Pass an empty
// orgID to list across every org (operator-only — callers must enforce that).
func (s *Store) ListAuditEvents(ctx context.Context, orgID uuid.UUID, opts ListAuditOptions) ([]AuditEvent, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 500 {
		opts.Limit = 500
	}

	// Build the WHERE clause incrementally so optional filters compose
	// without us having to write 2^N variant queries.
	q := `SELECT id, occurred_at, actor_kind, actor_user_id, actor_token_id,
	             org_id, action, COALESCE(target_type,''), target_id,
	             COALESCE(host(ip),''), COALESCE(user_agent,''),
	             COALESCE(request_id,''), details
	      FROM audit_event WHERE 1=1`
	args := []any{}
	if orgID != uuid.Nil {
		args = append(args, orgID)
		q += fmt.Sprintf(" AND org_id = $%d", len(args))
	}
	if !opts.Since.IsZero() {
		args = append(args, opts.Since)
		q += fmt.Sprintf(" AND occurred_at >= $%d", len(args))
	}
	if !opts.Until.IsZero() {
		args = append(args, opts.Until)
		q += fmt.Sprintf(" AND occurred_at < $%d", len(args))
	}
	if opts.Action != "" {
		args = append(args, opts.Action)
		q += fmt.Sprintf(" AND action = $%d", len(args))
	}
	args = append(args, opts.Limit)
	q += fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var details []byte
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.ActorKind,
			&e.ActorUserID, &e.ActorTokenID, &e.OrgID,
			&e.Action, &e.TargetType, &e.TargetID,
			&e.IP, &e.UserAgent, &e.RequestID, &details); err != nil {
			return nil, err
		}
		if len(details) > 0 {
			e.Details = json.RawMessage(details)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}


