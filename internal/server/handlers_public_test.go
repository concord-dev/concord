package server_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ─── Public ────────────────────────────────────────────────────────────

func TestHealth_NoAuth(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/healthz", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"status":"ok"}`, string(body))
}
