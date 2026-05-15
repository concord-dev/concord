package server_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReady_OK confirms the readiness probe pings every dep and reports a
// machine-readable per-dep breakdown on the happy path.
func TestReady_OK(t *testing.T) {
	h := newHarness(t)
	resp, raw := h.do(t, "GET", "/readyz", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.Equal(t, "ok", body.Status)
	assert.Equal(t, "ok", body.Checks["database"],
		"database probe must show ok when the pool is healthy")
}

// TestReady_DegradedWhenDBDown closes the pool out from under the server and
// asserts /readyz returns 503 with a degraded payload. /healthz must keep
// returning 200 — it is the liveness probe and must not flap when deps blip.
func TestReady_DegradedWhenDBDown(t *testing.T) {
	h := newHarness(t)
	// Force every subsequent pool operation to fail.
	h.st.Close()

	resp, raw := h.do(t, "GET", "/readyz", "", "")
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.Equal(t, "degraded", body.Status)
	assert.NotEqual(t, "ok", body.Checks["database"],
		"closed pool must surface as a non-ok database check")
	assert.NotEmpty(t, body.Checks["database"],
		"failing checks must carry an error message an operator can read")

	// Liveness must NOT flap when a dep is down — that's the whole point of
	// splitting the two probes.
	respLive, rawLive := h.do(t, "GET", "/healthz", "", "")
	assert.Equal(t, http.StatusOK, respLive.StatusCode)
	assert.JSONEq(t, `{"status":"ok"}`, string(rawLive))
}
