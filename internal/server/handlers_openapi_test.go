package server_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func TestOpenAPI_ServedAsYAML(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/openapi.yaml", "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/yaml", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(body), "openapi: 3.0.3")
	assert.Contains(t, string(body), "/v1/auth/login")
}

func TestDocs_ServesSwaggerUIShim(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/docs", "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")
	assert.Contains(t, string(body), "/openapi.yaml")
	assert.Contains(t, string(body), "swagger-ui")
}
