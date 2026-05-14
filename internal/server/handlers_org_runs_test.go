package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// ─── Async runs ───────────────────────────────────────────────────────

func TestCheck_ReturnsAcceptedAndPollSucceeds(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", h.apiToken)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, string(body))
	var enq struct {
		RunID   string `json:"run_id"`
		PollURL string `json:"poll_url"`
	}
	require.NoError(t, json.Unmarshal(body, &enq))
	assert.Contains(t, enq.PollURL, "/v1/orgs/"+h.org.Slug+"/runs/")

	var detail map[string]any
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp2, body2 := h.do(t, "GET", enq.PollURL, "", h.apiToken)
		require.Equal(t, http.StatusOK, resp2.StatusCode)
		require.NoError(t, json.Unmarshal(body2, &detail))
		if detail["status"] != "pending" && detail["status"] != "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Equal(t, "succeeded", detail["status"])

	// /findings lists the same run.
	respF, bodyF := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/findings", "", h.apiToken)
	require.Equal(t, http.StatusOK, respF.StatusCode)
	var findings struct {
		Findings []apiv1.Finding `json:"findings"`
		RunID    string          `json:"run_id"`
	}
	require.NoError(t, json.Unmarshal(bodyF, &findings))
	assert.Equal(t, enq.RunID, findings.RunID)
	assert.Equal(t, len(h.c.Controls), len(findings.Findings))
}

// ─── SSE ──────────────────────────────────────────────────────────────

func TestEvents_StreamsLifecycle(t *testing.T) {
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

	respCheck, _ := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", h.apiToken)
	require.Equal(t, http.StatusAccepted, respCheck.StatusCode)

	frames := make(chan sseFrame, 32)
	go func() { defer close(frames); readSSEFrames(resp.Body, frames) }()

	var sawStarted, sawCompleted bool
	deadline := time.After(15 * time.Second)
loop:
	for !sawCompleted {
		select {
		case f, ok := <-frames:
			if !ok {
				break loop
			}
			switch f.Event {
			case "run.started":
				sawStarted = true
			case "run.completed":
				sawCompleted = true
			}
		case <-deadline:
			t.Fatalf("timed out; started=%v completed=%v", sawStarted, sawCompleted)
		}
	}
	assert.True(t, sawStarted)
}
