package org

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

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
	StartedAt   time.Time        `json:"started_at"`
	CompletedAt time.Time        `json:"completed_at"`
	Summary     report.Summary   `json:"summary"`
	Findings    []apiv1.Finding  `json:"findings"`
}

// SubmitRun accepts a completed run from an agent. Auth is the existing API
// token (`Authorization: Bearer concord_...`). If the request also carries
// `X-Concord-Agent-Key-Id` + `X-Concord-Agent-Signature`, the server verifies
// the Ed25519 signature over the raw request body before persisting the run.
//
// 200 even when signature headers are missing — the customer's policy
// decides whether unsigned runs are acceptable (visible via run.source +
// run.signature_verified on the read side).
func (h *Handlers) SubmitRun(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())

	// Read raw body first — signature verification operates on bytes, JSON
	// canonicalization is intentionally out of scope.
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

	source, agentID, verified, vErr := h.verifyAgentSignature(r, body, p.Org.ID)
	if vErr != nil {
		httpx.Error(w, http.StatusUnauthorized, vErr.Error())
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
		OrgID:             p.Org.ID,
		TokenID:           p.TokenID,
		UserID:            p.UserID,
		AgentID:           agentID,
		AgentVersion:      sub.Agent.Version,
		Source:            source,
		SignatureVerified: verified,
		StartedAt:         sub.StartedAt,
		CompletedAt:       sub.CompletedAt,
		Summary:           summaryJSON,
		Findings:          findingsJSON,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	if agentID != nil {
		// Best-effort; failure here doesn't invalidate the run.
		_ = h.store.MarkAgentKeyUsed(r.Context(), *agentID)
	}

	slug := r.PathValue("slug")
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"run_id":             run.ID,
		"source":             run.Source,
		"signature_verified": run.SignatureVerified,
		"agent_id":           run.AgentID,
		"url":                fmt.Sprintf("/v1/orgs/%s/runs/%s", slug, run.ID),
	})
}

// verifyAgentSignature inspects the X-Concord-Agent-Key-Id and
// X-Concord-Agent-Signature headers. Returns (source, agentID, verified, err):
//
//   - both headers absent     → ("unsigned", nil, false, nil)
//   - both present + valid    → ("agent",    &id, true,  nil)
//   - exactly one present     → error (avoid silent downgrades)
//   - present but invalid sig → error
//   - unknown key id / wrong org / revoked → error (indistinguishable on purpose)
func (h *Handlers) verifyAgentSignature(r *http.Request, body []byte, orgID uuid.UUID) (store.RunSource, *uuid.UUID, bool, error) {
	keyIDHeader := r.Header.Get("X-Concord-Agent-Key-Id")
	sigHeader := r.Header.Get("X-Concord-Agent-Signature")

	switch {
	case keyIDHeader == "" && sigHeader == "":
		return store.RunSourceUnsigned, nil, false, nil
	case keyIDHeader == "" || sigHeader == "":
		return "", nil, false, errors.New("X-Concord-Agent-Key-Id and X-Concord-Agent-Signature must both be present or both absent")
	}

	keyID, err := uuid.Parse(keyIDHeader)
	if err != nil {
		return "", nil, false, errors.New("invalid agent key id header")
	}
	sig, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil {
		return "", nil, false, errors.New("X-Concord-Agent-Signature must be base64 (standard encoding)")
	}
	if len(sig) != ed25519.SignatureSize {
		return "", nil, false, errors.New("agent signature length is wrong")
	}

	key, err := h.store.GetAgentKey(r.Context(), orgID, keyID)
	if err != nil {
		// Don't distinguish "no such key" from "revoked" from "wrong org".
		return "", nil, false, errors.New("unknown or revoked agent key")
	}
	if !ed25519.Verify(ed25519.PublicKey(key.PublicKey), body, sig) {
		return "", nil, false, errors.New("agent signature verification failed")
	}
	return store.RunSourceAgent, &key.ID, true, nil
}
