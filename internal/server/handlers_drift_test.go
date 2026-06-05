package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

func submitRun(t *testing.T, h *harness, auth string, findingsJSON string) string {
	t.Helper()
	body := fmt.Sprintf(`{
        "agent":        {"version":"test"},
        "started_at":   "2026-05-16T00:00:00Z",
        "completed_at": "2026-05-16T00:01:00Z",
        "summary":      {},
        "findings":     %s
    }`, findingsJSON)
	resp, raw := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", body, auth)
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "submit: %s", raw)
	var got struct {
		RunID string `json:"run_id"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	return got.RunID
}

func TestSubmitRun_FirstRunProducesNoDriftEvents(t *testing.T) {
	h := newHarness(t)
	auth := "Bearer " + h.apiToken
	_ = auth // unused — h.do takes the bare token
	submitRun(t, h, h.apiToken, `[{"control_id":"a","status":"pass"}]`)

	events, err := h.st.ListDriftEvents(context.Background(), h.org.ID, store.ListDriftOptions{})
	require.NoError(t, err)
	assert.Empty(t, events,
		"first-ever run has nothing to compare to — drift detection must short-circuit silently")
}

func TestSubmitRun_PassToFailTransitionProducesDriftEvent(t *testing.T) {
	h := newHarness(t)
	submitRun(t, h, h.apiToken, `[{"control_id":"a","status":"pass"}]`)
	secondRunID := submitRun(t, h, h.apiToken,
		`[{"control_id":"a","status":"fail","messages":["root key detected"]}]`)

	events, err := h.st.ListDriftEvents(context.Background(), h.org.ID, store.ListDriftOptions{})
	require.NoError(t, err)
	if assert.Len(t, events, 1, "exactly one transition expected: a pass→fail on control 'a'") {
		got := events[0]
		assert.Equal(t, "a", got.ControlID)
		assert.Equal(t, "pass", got.From)
		assert.Equal(t, "fail", got.To)
		assert.Equal(t, "root key detected", got.Rationale,
			"rationale must be the new finding's first message — that's the actionable detail")
		assert.Equal(t, secondRunID, got.RunID.String())
		require.NotNil(t, got.PriorRunID, "prior_run_id must be set on every non-first transition")
	}
}

func TestSubmitRun_StableRunsProduceNoDrift(t *testing.T) {
	h := newHarness(t)
	submitRun(t, h, h.apiToken, `[{"control_id":"a","status":"pass"}]`)
	submitRun(t, h, h.apiToken, `[{"control_id":"a","status":"pass"}]`)

	events, _ := h.st.ListDriftEvents(context.Background(), h.org.ID, store.ListDriftOptions{})
	assert.Empty(t, events,
		"stable run-over-run must not emit drift — that's the whole point of the pass/fail comparison")
}

func TestSubmitRun_MassRegressionRecordsOneRowPerControl(t *testing.T) {
	h := newHarness(t)
	submitRun(t, h, h.apiToken,
		`[{"control_id":"a","status":"pass"},
		  {"control_id":"b","status":"pass"},
		  {"control_id":"c","status":"pass"}]`)
	submitRun(t, h, h.apiToken,
		`[{"control_id":"a","status":"fail"},
		  {"control_id":"b","status":"fail"},
		  {"control_id":"c","status":"pass"}]`) // c is stable

	events, _ := h.st.ListDriftEvents(context.Background(), h.org.ID, store.ListDriftOptions{})
	assert.Len(t, events, 2,
		"two regressions + one stable control → two rows; stable controls must NOT show up")

	ids := map[string]bool{}
	for _, e := range events {
		ids[e.ControlID] = true
		assert.Equal(t, "pass", e.From)
		assert.Equal(t, "fail", e.To)
	}
	assert.True(t, ids["a"] && ids["b"])
	assert.False(t, ids["c"])
}

func TestDriftEndpoint_AppliesFromToFilter(t *testing.T) {
	h := newHarness(t)
	submitRun(t, h, h.apiToken,
		`[{"control_id":"a","status":"pass"},
		  {"control_id":"b","status":"fail"}]`)
	submitRun(t, h, h.apiToken,
		`[{"control_id":"a","status":"fail"},
		  {"control_id":"b","status":"pass"}]`) // b is a remediation

	sessionToken := h.login(t)
	resp, raw := h.do(t, "GET",
		"/v1/orgs/"+h.org.Slug+"/drift?from=pass&to=fail",
		"", sessionToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var events []store.DriftEvent
	require.NoError(t, json.Unmarshal(raw, &events))
	require.Len(t, events, 1, "filter must collapse to just the regression — remediation excluded")
	assert.Equal(t, "a", events[0].ControlID)
}

func TestDriftEndpoint_RunIDSubviewIgnoresOtherFilters(t *testing.T) {
	h := newHarness(t)
	submitRun(t, h, h.apiToken, `[{"control_id":"a","status":"pass"}]`)
	r2 := submitRun(t, h, h.apiToken, `[{"control_id":"a","status":"fail"}]`)

	sessionToken := h.login(t)
	resp, raw := h.do(t, "GET",
		"/v1/orgs/"+h.org.Slug+"/drift?run_id="+r2,
		"", sessionToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var events []store.DriftEvent
	require.NoError(t, json.Unmarshal(raw, &events))
	require.Len(t, events, 1)
	assert.Equal(t, r2, events[0].RunID.String())
}
