package auditpackage

import (
	"archive/zip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/store"
)

type Options struct {
	Since time.Time
	Until time.Time

	MaxRuns int
	MaxAuditEvents int
	MaxDriftEvents int

	RequestedBy string
}

type Metadata struct {
	Version       string         `json:"version"`
	GeneratedAt   time.Time      `json:"generated_at"`
	RequestedBy   string         `json:"requested_by,omitempty"`
	Organization  store.Organization `json:"organization"`
	WindowSince   *time.Time     `json:"window_since,omitempty"`
	WindowUntil   *time.Time     `json:"window_until,omitempty"`
	Counts        Counts         `json:"counts"`
}

type Counts struct {
	Runs        int `json:"runs"`
	AuditEvents int `json:"audit_events"`
	DriftEvents int `json:"drift_events"`
	HasFindings bool `json:"has_findings"`
}

const (
	formatVersion = "1"

	defaultMaxRuns        = 100
	defaultMaxAuditEvents = 5000
	defaultMaxDriftEvents = 5000
)

func Build(ctx context.Context, s *store.Store, orgID uuid.UUID, opts Options, w io.Writer) (Metadata, error) {
	if s == nil {
		return Metadata{}, errors.New("auditpackage: store is required")
	}
	if opts.MaxRuns <= 0 {
		opts.MaxRuns = defaultMaxRuns
	}
	if opts.MaxAuditEvents <= 0 {
		opts.MaxAuditEvents = defaultMaxAuditEvents
	}
	if opts.MaxDriftEvents <= 0 {
		opts.MaxDriftEvents = defaultMaxDriftEvents
	}

	org, err := s.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return Metadata{}, fmt.Errorf("auditpackage: load org: %w", err)
	}

	zw := zip.NewWriter(w)

	meta := Metadata{
		Version:      formatVersion,
		GeneratedAt:  time.Now().UTC(),
		RequestedBy:  opts.RequestedBy,
		Organization: org,
	}
	if !opts.Since.IsZero() {
		s := opts.Since.UTC()
		meta.WindowSince = &s
	}
	if !opts.Until.IsZero() {
		u := opts.Until.UTC()
		meta.WindowUntil = &u
	}

	latest, err := s.GetLatestSucceededRun(ctx, orgID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return meta, fmt.Errorf("auditpackage: latest run: %w", err)
	}
	if err == nil {
		meta.Counts.HasFindings = true
		if werr := writeRawJSON(zw, "findings/latest.json", latest.Findings); werr != nil {
			return meta, werr
		}
		if werr := writeRawJSON(zw, "findings/latest-summary.json", latest.Summary); werr != nil {
			return meta, werr
		}
		if werr := writeJSON(zw, "findings/latest-run.json", map[string]any{
			"run_id":       latest.ID,
			"started_at":   latest.StartedAt,
			"completed_at": latest.CompletedAt,
			"status":       latest.Status,
			"source":       latest.Source,
		}); werr != nil {
			return meta, werr
		}
	}

	runs, err := s.ListRuns(ctx, orgID, opts.MaxRuns)
	if err != nil {
		return meta, fmt.Errorf("auditpackage: list runs: %w", err)
	}
	meta.Counts.Runs = len(runs)
	if err := writeRunsCSV(zw, runs); err != nil {
		return meta, err
	}

	auditEvents, err := s.ListAuditEvents(ctx, orgID, store.ListAuditOptions{
		Since: opts.Since, Until: opts.Until, Limit: opts.MaxAuditEvents,
	})
	if err != nil {
		return meta, fmt.Errorf("auditpackage: list audit events: %w", err)
	}
	meta.Counts.AuditEvents = len(auditEvents)
	if err := writeAuditEventsCSV(zw, auditEvents); err != nil {
		return meta, err
	}

	driftEvents, err := s.ListDriftEvents(ctx, orgID, store.ListDriftOptions{
		Since: opts.Since, Until: opts.Until, Limit: opts.MaxDriftEvents,
	})
	if err != nil {
		return meta, fmt.Errorf("auditpackage: list drift events: %w", err)
	}
	meta.Counts.DriftEvents = len(driftEvents)
	if err := writeDriftEventsCSV(zw, driftEvents); err != nil {
		return meta, err
	}

	overrides, err := s.ListControlOverrides(ctx, orgID)
	if err != nil {
		return meta, fmt.Errorf("auditpackage: list overrides: %w", err)
	}
	if err := writeJSON(zw, "controls-overrides.json", overrides); err != nil {
		return meta, err
	}

	if err := writeJSON(zw, "metadata.json", meta); err != nil {
		return meta, err
	}

	if err := zw.Close(); err != nil {
		return meta, fmt.Errorf("auditpackage: close zip: %w", err)
	}
	return meta, nil
}

func writeJSON(zw *zip.Writer, name string, body any) error {
	f, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("auditpackage: create %s: %w", name, err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(body); err != nil {
		return fmt.Errorf("auditpackage: write %s: %w", name, err)
	}
	return nil
}

func writeRawJSON(zw *zip.Writer, name string, raw []byte) error {
	f, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("auditpackage: create %s: %w", name, err)
	}
	if len(raw) == 0 {
		_, err = f.Write([]byte("null"))
	} else {
		_, err = f.Write(raw)
	}
	if err != nil {
		return fmt.Errorf("auditpackage: write %s: %w", name, err)
	}
	return nil
}

func writeRunsCSV(zw *zip.Writer, runs []store.Run) error {
	f, err := zw.Create("runs.csv")
	if err != nil {
		return fmt.Errorf("auditpackage: create runs.csv: %w", err)
	}
	cw := csv.NewWriter(f)
	if err := cw.Write([]string{
		"id", "status", "source", "started_at", "completed_at",
		"error_message", "agent_version",
		"triggered_by_token", "triggered_by_user",
	}); err != nil {
		return err
	}
	for _, r := range runs {
		completed := ""
		if r.CompletedAt != nil {
			completed = r.CompletedAt.UTC().Format(time.RFC3339Nano)
		}
		if err := cw.Write([]string{
			r.ID.String(),
			string(r.Status),
			string(r.Source),
			r.StartedAt.UTC().Format(time.RFC3339Nano),
			completed,
			r.ErrorMessage,
			r.AgentVersion,
			uuidOrEmpty(r.TriggeredByToken),
			uuidOrEmpty(r.TriggeredByUser),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func writeAuditEventsCSV(zw *zip.Writer, events []store.AuditEvent) error {
	f, err := zw.Create("audit-events.csv")
	if err != nil {
		return fmt.Errorf("auditpackage: create audit-events.csv: %w", err)
	}
	cw := csv.NewWriter(f)
	if err := cw.Write([]string{
		"id", "occurred_at", "actor_kind", "actor_user_id", "actor_token_id",
		"action", "target_type", "target_id", "ip", "user_agent",
		"request_id", "details_json",
	}); err != nil {
		return err
	}
	for _, e := range events {
		if err := cw.Write([]string{
			e.ID.String(),
			e.OccurredAt.UTC().Format(time.RFC3339Nano),
			string(e.ActorKind),
			uuidOrEmpty(e.ActorUserID),
			uuidOrEmpty(e.ActorTokenID),
			e.Action,
			e.TargetType,
			uuidOrEmpty(e.TargetID),
			e.IP,
			e.UserAgent,
			e.RequestID,
			string(e.Details),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func writeDriftEventsCSV(zw *zip.Writer, events []store.DriftEvent) error {
	f, err := zw.Create("drift-events.csv")
	if err != nil {
		return fmt.Errorf("auditpackage: create drift-events.csv: %w", err)
	}
	cw := csv.NewWriter(f)
	if err := cw.Write([]string{
		"id", "occurred_at", "run_id", "prior_run_id",
		"control_id", "from_status", "to_status", "rationale",
	}); err != nil {
		return err
	}
	for _, e := range events {
		if err := cw.Write([]string{
			e.ID.String(),
			e.OccurredAt.UTC().Format(time.RFC3339Nano),
			e.RunID.String(),
			uuidOrEmpty(e.PriorRunID),
			e.ControlID,
			e.From,
			e.To,
			e.Rationale,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func uuidOrEmpty(p *uuid.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

