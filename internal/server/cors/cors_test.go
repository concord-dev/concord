package cors_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server/cors"
)

func trivialHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
}

func TestNoOriginConfigured_PassesThroughUnchanged(t *testing.T) {
	mw := cors.New(cors.Config{}) // empty allowlist == disabled
	srv := httptest.NewServer(mw(trivialHandler()))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest("GET", srv.URL+"/anything", nil)
	req.Header.Set("Origin", "https://app.example.com")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, "ok", string(body), "inner handler must still run")
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"),
		"disabled CORS must not advertise an allowed origin")
}

func TestAllowedOrigin_AddsHeaders(t *testing.T) {
	allowed := "https://app.example.com"
	mw := cors.New(cors.Config{AllowedOrigins: []string{allowed}})
	srv := httptest.NewServer(mw(trivialHandler()))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest("GET", srv.URL+"/x", nil)
	req.Header.Set("Origin", allowed)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, allowed, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"),
		"Authorization-bearing API must opt in to credentials")
	assert.Contains(t, resp.Header.Get("Access-Control-Expose-Headers"), "Location",
		"JS must be able to read the Location header on 201/202 responses")
	assert.Contains(t, resp.Header.Values("Vary"), "Origin",
		"Vary: Origin is mandatory so caches don't poison across origins")
}

func TestDisallowedOrigin_NoCORSHeadersButRequestStillServed(t *testing.T) {
	mw := cors.New(cors.Config{AllowedOrigins: []string{"https://app.example.com"}})
	srv := httptest.NewServer(mw(trivialHandler()))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest("GET", srv.URL+"/x", nil)
	req.Header.Set("Origin", "https://attacker.example")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, "ok", string(body),
		"the server still serves the response — the browser is the one that blocks JS from reading it")
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"),
		"unknown origin must NOT get an Allow-Origin header")
	assert.Contains(t, resp.Header.Values("Vary"), "Origin",
		"Vary: Origin still required so a CDN doesn't cache a different origin's response")
}

func TestNoOriginHeader_PassesThroughForCurlAndAgents(t *testing.T) {
	mw := cors.New(cors.Config{AllowedOrigins: []string{"https://app.example.com"}})
	srv := httptest.NewServer(mw(trivialHandler()))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/x")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	assert.Equal(t, "ok", string(body))
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Credentials"))
}

func TestPreflight_AllowedOrigin_Returns204WithoutCallingHandler(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("preflight must NOT call the inner handler")
	})
	allowed := "https://app.example.com"
	mw := cors.New(cors.Config{
		AllowedOrigins: []string{allowed},
		MaxAge:         12 * time.Minute,
	})
	srv := httptest.NewServer(mw(inner))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest("OPTIONS", srv.URL+"/v1/orgs/x/runs", nil)
	req.Header.Set("Origin", allowed)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type, Sentry-Trace")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, allowed, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "POST")
	allowedHdrs := resp.Header.Get("Access-Control-Allow-Headers")
	for _, want := range []string{"Authorization", "Content-Type", "Sentry-Trace"} {
		assert.Contains(t, allowedHdrs, want,
			"preflight should echo back the headers the browser asked for")
	}
	assert.Equal(t, "720", resp.Header.Get("Access-Control-Max-Age"),
		"12-minute MaxAge should serialize as 720 seconds")
	vary := strings.Join(resp.Header.Values("Vary"), ",")
	assert.Contains(t, vary, "Access-Control-Request-Method")
	assert.Contains(t, vary, "Access-Control-Request-Headers")
}

func TestPreflight_DisallowedOrigin_204WithoutCORSHeaders(t *testing.T) {
	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		innerCalled = true
	})
	mw := cors.New(cors.Config{AllowedOrigins: []string{"https://app.example.com"}})
	srv := httptest.NewServer(mw(inner))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest("OPTIONS", srv.URL+"/x", nil)
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode,
		"still 204 — but the browser will refuse the cross-origin request because no Allow-Origin came back")
	assert.False(t, innerCalled, "preflight must not call inner handler regardless of origin match")
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Methods"))
}

func TestPreflight_WithoutRequestMethodHeader_IsTreatedAsRegularOPTIONS(t *testing.T) {
	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusNotFound)
	})
	mw := cors.New(cors.Config{AllowedOrigins: []string{"https://app.example.com"}})
	srv := httptest.NewServer(mw(inner))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest("OPTIONS", srv.URL+"/x", nil)
	req.Header.Set("Origin", "https://app.example.com")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.True(t, innerCalled, "non-preflight OPTIONS must fall through to inner handler")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
