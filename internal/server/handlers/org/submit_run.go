package org

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/concord-dev/concord/internal/report"
	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

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

	h.broadcast(run, summaryJSON)

	slug := r.PathValue("slug")
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"run_id": run.ID,
		"source": run.Source,
		"url":    fmt.Sprintf("/v1/orgs/%s/runs/%s", slug, run.ID),
	})
}
