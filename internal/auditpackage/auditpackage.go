// Package auditpackage builds a self-contained ZIP archive of compliance
// evidence for one organization: latest findings, recent run history,
// drift transitions, and the audit-event trail. External auditors export
// this once per engagement and walk away with everything they need to
// produce a SOC 2 / ISO 27001 evidence appendix.
//
// Output is streamed through an archive/zip writer so a giant org with
// 10k+ audit events doesn't materialize the whole bundle in memory.
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

// Options narrows the bundle to a time window and caps recent-history
// rows. Zero values map to defensive defaults — see Build's docstring
// for the resolved policy.
type Options struct {
	// Since / Until bound the audit_event and drift_event extracts so a
	// long-lived org doesn't ship 5 years of every change. Zero Since
	// means "no lower bound"; zero Until means "now".
	Since time.Time
	Until time.Time

	// MaxRuns caps the run-history CSV. 0 → 100.
	MaxRuns int
	// MaxAuditEvents caps audit_event rows. 0 → 5000.
	MaxAuditEvents int
	// MaxDriftEvents caps drift_event rows. 0 → 5000.
	MaxDriftEvents int

	// RequestedBy is recorded in metadata.json so the bundle is
	// attributable. Pass the auditor's email or "operator" depending on
	// the call site.
	RequestedBy string
}

// Metadata is the top-level descriptor written to metadata.json. Stable
// shape — external tooling parses this to know what's inside the zip.
type Metadata struct {
	Version       string         `json:"version"`
	GeneratedAt   time.Time      `json:"generated_at"`
	RequestedBy   string         `json:"requested_by,omitempty"`
	Organization  store.Organization `json:"organization"`
	WindowSince   *time.Time     `json:"window_since,omitempty"`
	WindowUntil   *time.Time     `json:"window_until,omitempty"`
	Counts        Counts         `json:"counts"`
}

// Counts is the per-section row counter, also surfaced in metadata.json
// so a downstream pipeline can decide whether to fetch more (the caps
// are documented + visible).
type Counts struct {
	Runs        int `json:"runs"`
	AuditEvents int `json:"audit_events"`
	DriftEvents int `json:"drift_events"`
	HasFindings bool `json:"has_findings"`
}

const (
	// formatVersion is the metadata.json schema marker. Bump if the
	// archive layout changes in a non-backwards-compatible way so
	// downstream parsers can reject unknown shapes loudly.
	formatVersion = "1"

	defaultMaxRuns        = 100
	defaultMaxAuditEvents = 5000
	defaultMaxDriftEvents = 5000
)

// Build streams a complete audit-package ZIP for orgID into w. Errors
// return early before any partial archive is written when possible; once
// the zip writer is open, errors mid-stream cancel the archive (the zip
// trailer is never written, so consumers see a truncated/invalid zip
// rather than a misleading "empty looks fine" archive).
//
// Filesystem layout of the ZIP:
//
//	metadata.json                 top-level descriptor
//	findings/latest.json          latest succeeded run's findings (JSON array)
//	findings/latest-summary.json  the run summary (counts by status)
//	runs.csv                      recent runs (id, status, started_at, ...)
//	audit-events.csv              audit_event rows in the window
//	drift-events.csv              drift_event rows in the window
//	controls-overrides.json       per-org control overrides (current state)
//
// Callers should set the HTTP Content-Type to "application/zip" and a
// Content-Disposition with a sensible filename (`audit-package-<slug>-<ts>.zip`).
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
	// IMPORTANT: zw.Close writes the zip central-directory trailer.
	// We call it explicitly at the end (no defer) so a build error
	// leaves the archive deliberately invalid — better than a truncated
	// archive that LOOKS valid but is missing a section.

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

	// Latest findings — point-in-time evidence. An org with no succeeded
	// runs yet still produces a valid bundle; HasFindings flags the case.
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
		// Also drop a tiny pointer file so consumers see which run
		// produced the findings without parsing the JSON.
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

	// Metadata last so its counts reflect everything actually written.
	if err := writeJSON(zw, "metadata.json", meta); err != nil {
		return meta, err
	}

	if err := zw.Close(); err != nil {
		return meta, fmt.Errorf("auditpackage: close zip: %w", err)
	}
	return meta, nil
}

// writeJSON marshals body and writes it to one zip entry. Indented for
// human readability — the archive is meant for auditors, who often
// open the files in a plain text editor.
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

// writeRawJSON streams a JSON []byte (already encoded by Postgres' JSONB
// output) into one zip entry without re-marshaling. Avoids the cost of
// a parse+re-encode on findings arrays that may carry thousands of items.
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

