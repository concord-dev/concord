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

var tracer = otel.Tracer("github.com/concord-dev/concord/internal/server/handlers/org")

const maxSubmissionBytes = 25 * 1024 * 1024

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

func (h *Handlers) detectAndPersistDrift(ctx context.Context, run store.Run, currentFindings []apiv1.Finding) []bus.Transition {
	ctx, span := tracer.Start(ctx, "drift.detect_and_persist",
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
	}
	log.Info("drift detected",
		slog.String("run_id", run.ID.String()),
		slog.String("prior_run_id", priorRunID.String()),
		slog.Int("transitions", len(out)))
	return out
}
