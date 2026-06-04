package org

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/report"
	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/server/drift"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// tracer is the package-level Tracer used for custom spans inside the
// org handlers. Resolves to a no-op when tracing is disabled, so the
// `tr.Start(...)` calls below are zero-cost in that configuration.
var tracer = otel.Tracer("github.com/concord-dev/concord/internal/server/handlers/org")

// maxSubmissionBytes caps the request body so a misbehaving (or malicious)
// agent can't DoS the server with a 5GB findings array. 25MB comfortably
// covers tens of thousands of findings while keeping memory bounded.
const maxSubmissionBytes = 25 * 1024 * 1024

// agentSubmission is the wire shape an agent POSTs. Times come from the
// agent's clock — we don't reject skew, but the run is also stamped with the
// server's receive time via the row's created_at column so audit views can
// distinguish "when the agent said it ran" from "when we received it".
type agentSubmission struct {
	Agent struct {
		Version         string `json:"version"`
		ControlsVersion string `json:"controls_version,omitempty"`
	} `json:"agent"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt time.Time       `json:"completed_at"`
	Summary     report.Summary  `json:"summary"`
	Findings    []apiv1.Finding `json:"findings"`
}

// SubmitRun accepts a completed run from an agent. Auth is the existing API
// token (`Authorization: Bearer concord_...`); the same audit/revocation
// surface that secures every other org route covers this one. No additional
// signing — the token *is* the agent's identity.
//
// On success the bus is told `run.completed` so SSE subscribers see the run
// in real time, and any registered webhooks fire (best-effort, asynchronously).
func (h *Handlers) SubmitRun(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())

	body, err := io.ReadAll(io.LimitReader(r.Body, maxSubmissionBytes+1))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "reading body: "+err.Error())
		return
	}
	if len(body) > maxSubmissionBytes {
		httpx.Error(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("submission exceeds %d bytes", maxSubmissionBytes))
		return
	}

	var sub agentSubmission
	if err := json.Unmarshal(body, &sub); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if sub.StartedAt.IsZero() || sub.CompletedAt.IsZero() {
		httpx.Error(w, http.StatusBadRequest, "`started_at` and `completed_at` are required")
		return
	}
	if sub.Findings == nil {
		// Empty `findings` is fine (controls library was empty); nil isn't —
		// reject so an agent bug that forgets to populate the array surfaces
		// loudly instead of silently storing an empty run.
		httpx.Error(w, http.StatusBadRequest, "`findings` must be present (use [] for empty)")
		return
	}

	summaryJSON, _ := json.Marshal(sub.Summary)
	findingsJSON, _ := json.Marshal(sub.Findings)

	run, err := h.store.SubmitRun(r.Context(), store.SubmitRunParams{
		OrgID:        p.Org.ID,
		TokenID:      p.TokenID,
		UserID:       p.UserID,
		AgentVersion: sub.Agent.Version,
		Source:       store.RunSourceAgent,
		StartedAt:    sub.StartedAt,
		CompletedAt:  sub.CompletedAt,
		Summary:      summaryJSON,
		Findings:     findingsJSON,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Drift detection: compare the freshly-inserted run's findings to the
	// prior run's. detectAndPersistDrift handles the "no prior" case (first
	// run for the org) and any errors itself — its log calls are loud
	// enough for an operator but never failed the user's submission.
	transitions := h.detectAndPersistDrift(r.Context(), run, sub.Findings)

	h.broadcast.RunCompleted(run, summaryJSON)
	h.broadcast.DriftDetected(run, transitions)

	slug := r.PathValue("slug")
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"run_id": run.ID,
		"source": run.Source,
		"url":    fmt.Sprintf("/v1/orgs/%s/runs/%s", slug, run.ID),
	})
}

// detectAndPersistDrift loads the prior run's findings, runs the drift
// detector against the new submission, persists every transition as a
// drift_event row, and returns the transitions (re-cast to bus.Transition)
// for publication. Returns nil on the first-ever run (no prior to
// compare to) and logs but swallows every infrastructure error: a single
// failure here must NEVER reject a legit submission.
func (h *Handlers) detectAndPersistDrift(ctx context.Context, run store.Run, currentFindings []apiv1.Finding) []bus.Transition {
	ctx, span := tracer.Start(ctx, "drift.detect_and_persist",
		// org_id + run_id are stable, low-cardinality enough for span
		// attrs (one tag per request is fine) and let an investigator
		// pivot from a drift event back to the originating run.
		// findings_count helps explain unusually long detection times.
	)
	span.SetAttributes(
		attribute.String("concord.org_id", run.OrgID.String()),
		attribute.String("concord.run_id", run.ID.String()),
		attribute.Int("concord.findings_count", len(currentFindings)),
	)
	defer span.End()

	log := logx.FromContext(ctx)
	priorFindingsRaw, priorRunID, err := h.store.GetPreviousRunFindings(ctx, run.OrgID, run.ID)
	if errors.Is(err, store.ErrNotFound) {
		span.SetAttributes(attribute.Bool("concord.first_run", true))
		return nil // first run for this org — no prior to compare to
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "load prior run")
		log.Error("drift: load prior run failed",
			slog.String("org_id", run.OrgID.String()),
			slog.String("err", err.Error()))
		return nil
	}
	var prior []apiv1.Finding
	if len(priorFindingsRaw) > 0 {
		if err := json.Unmarshal(priorFindingsRaw, &prior); err != nil {
			log.Error("drift: parse prior findings failed",
				slog.String("prior_run_id", priorRunID.String()),
				slog.String("err", err.Error()))
			return nil
		}
	}

	transitions := drift.Detect(prior, currentFindings)
	span.SetAttributes(attribute.Int("concord.transitions", len(transitions)))
	if len(transitions) == 0 {
		return nil
	}

	rows := make([]store.RecordDriftEventParams, 0, len(transitions))
	out := make([]bus.Transition, 0, len(transitions))
	priorRunRef := priorRunID
	for _, t := range transitions {
		rows = append(rows, store.RecordDriftEventParams{
			OrgID:      run.OrgID,
			RunID:      run.ID,
			PriorRunID: &priorRunRef,
			ControlID:  t.ControlID,
			From:       string(t.From),
			To:         string(t.To),
			Rationale:  t.Rationale,
		})
		out = append(out, bus.Transition{
			ControlID: t.ControlID,
			From:      string(t.From),
			To:        string(t.To),
			Rationale: t.Rationale,
		})
	}
	if err := h.store.RecordDriftEvents(ctx, rows); err != nil {
		log.Error("drift: persist failed",
			slog.String("run_id", run.ID.String()),
			slog.Int("transitions", len(rows)),
			slog.String("err", err.Error()))
		// Still publish on the bus — losing the audit trail is bad, but
		// losing the page-someone webhook would be worse. Trade-off
		// chosen deliberately.
	}
	// Surface a friendly summary on the access log so operators reading
	// logs see drift the way they see auth events.
	log.Info("drift detected",
		slog.String("run_id", run.ID.String()),
		slog.String("prior_run_id", priorRunID.String()),
		slog.Int("transitions", len(out)))
	return out
}
