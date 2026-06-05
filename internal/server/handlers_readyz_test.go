package server_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestReady_DegradedWhenDBDown(t *testing.T) {
	h := newHarness(t)
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

	respLive, rawLive := h.do(t, "GET", "/healthz", "", "")
	assert.Equal(t, http.StatusOK, respLive.StatusCode)
	assert.JSONEq(t, `{"status":"ok"}`, string(rawLive))
}
