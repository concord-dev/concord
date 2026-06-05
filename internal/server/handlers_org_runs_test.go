package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func TestSubmitRun_StoresAndShowsUpInFindings(t *testing.T) {
	h := newHarness(t)
	runID := h.submitTestRun(t, h.apiToken,
		`[{"control_id":"CC1.1","status":"pass","framework":"soc2"}]`)
	require.NotEmpty(t, runID)

	resp, body := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/runs/"+runID, "", h.apiToken)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var run map[string]any
	require.NoError(t, json.Unmarshal(body, &run))
	assert.Equal(t, "succeeded", run["status"])
	assert.Equal(t, "agent", run["source"])

	respF, bodyF := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/findings", "", h.apiToken)
	require.Equal(t, http.StatusOK, respF.StatusCode)
	var findings struct {
		RunID    string           `json:"run_id"`
		Findings []map[string]any `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(bodyF, &findings))
	assert.Equal(t, runID, findings.RunID)
	require.Len(t, findings.Findings, 1)
	assert.Equal(t, "CC1.1", findings.Findings[0]["control_id"])
}

func TestSubmitRun_RejectsNilFindings(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC().Format(time.RFC3339)
	body := fmt.Sprintf(`{"agent":{"version":"t"},"started_at":%q,"completed_at":%q,"summary":{}}`, now, now)
	resp, raw := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", body, h.apiToken)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(raw), "findings")
}

func TestSubmitRun_RejectsMissingTimestamps(t *testing.T) {
	h := newHarness(t)
	body := `{"agent":{"version":"t"},"summary":{},"findings":[]}`
	resp, raw := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", body, h.apiToken)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(raw), "started_at")
}


func TestEvents_StreamsRunCompletedOnSubmit(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET", h.srv.URL+"/v1/orgs/"+h.org.Slug+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+h.apiToken)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Eventually(t, func() bool {
		return h.c.Bus().SubscriberCount(h.org.ID) > 0
	}, 2*time.Second, 10*time.Millisecond)

	frames := make(chan sseFrame, 32)
	go func() { defer close(frames); readSSEFrames(resp.Body, frames) }()

	// Submit an agent run — server should broadcast run.completed.
	h.submitTestRun(t, h.apiToken, "[]")

	deadline := time.After(5 * time.Second)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatal("SSE stream closed before run.completed arrived")
			}
			if f.Event == "run.completed" {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for run.completed SSE event")
		}
	}
}
