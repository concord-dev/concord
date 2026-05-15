package org

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/report"
	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Check creates a run, enqueues it on the background worker, and responds 202
// Accepted with the run id. Clients poll GET /runs/{id}.
func (h *Handlers) Check(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.PrincipalFrom(r.Context())
	if !ok {
		httpx.Error(w, http.StatusInternalServerError, "principal missing")
		return
	}
	run, err := h.store.CreateRun(r.Context(), store.CreateRunParams{
		OrgID: p.Org.ID, TokenID: p.TokenID, UserID: p.UserID,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "creating run: "+err.Error())
		return
	}
	if err := h.worker.Enqueue(p.Org.ID, run.ID); err != nil {
		_ = h.store.FailRun(context.Background(), run.ID, err.Error())
		httpx.Error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	slug := r.PathValue("slug")
	pollURL := fmt.Sprintf("/v1/orgs/%s/runs/%s", slug, run.ID)
	w.Header().Set("Location", pollURL)
	httpx.JSON(w, http.StatusAccepted, map[string]any{
		"run_id":     run.ID,
		"status":     string(store.RunPending),
		"poll_url":   pollURL,
		"started_at": run.StartedAt,
	})
}

// Findings returns the most recent succeeded run's findings.
func (h *Handlers) Findings(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	runs, err := h.store.ListRuns(r.Context(), p.Org.ID, 20)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, r0 := range runs {
		if r0.Status != store.RunSucceeded {
			continue
		}
		full, err := h.store.GetRun(r.Context(), p.Org.ID, r0.ID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeFindingsEnvelope(w, full)
		return
	}
	httpx.Error(w, http.StatusNotFound, "no succeeded run yet — POST /v1/orgs/{slug}/check first")
}

// ListRuns returns the last 50 runs without summary/findings blobs.
func (h *Handlers) ListRuns(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	runs, err := h.store.ListRuns(r.Context(), p.Org.ID, 50)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	type listEntry struct {
		ID           uuid.UUID  `json:"id"`
		Status       string     `json:"status"`
		StartedAt    time.Time  `json:"started_at"`
		CompletedAt  *time.Time `json:"completed_at,omitempty"`
		ErrorMessage string     `json:"error_message,omitempty"`
	}
	out := make([]listEntry, 0, len(runs))
	for _, r0 := range runs {
		out = append(out, listEntry{
			ID: r0.ID, Status: string(r0.Status), StartedAt: r0.StartedAt,
			CompletedAt: r0.CompletedAt, ErrorMessage: r0.ErrorMessage,
		})
	}
	httpx.JSON(w, http.StatusOK, out)
}

// GetRun returns one run with its full findings envelope.
func (h *Handlers) GetRun(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	runID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid run id")
		return
	}
	run, err := h.store.GetRun(r.Context(), p.Org.ID, runID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeFindingsEnvelope(w, run)
}

// writeFindingsEnvelope renders a Run with parsed summary + findings JSON.
// Malformed blobs fall through as their zero values rather than 500.
func writeFindingsEnvelope(w http.ResponseWriter, run store.Run) {
	var summary report.Summary
	var findings []apiv1.Finding
	if len(run.Summary) > 0 {
		_ = json.Unmarshal(run.Summary, &summary)
	}
	if len(run.Findings) > 0 {
		_ = json.Unmarshal(run.Findings, &findings)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"run_id":        run.ID,
		"status":        run.Status,
		"started_at":    run.StartedAt,
		"completed_at":  run.CompletedAt,
		"error_message": run.ErrorMessage,
		"summary":       summary,
		"findings":      findings,
	})
}
