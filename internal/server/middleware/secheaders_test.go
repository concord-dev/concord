package middleware_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server/middleware"
)

func ok() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
}

func TestSecurityHeaders_DefaultsPresentOnEveryResponse(t *testing.T) {
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})
	srv := httptest.NewServer(mw(ok()))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/anything")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"),
		"nosniff must be set on every response — there is no scenario where we want browsers MIME-sniffing our JSON")
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"),
		"DENY is the safe default — the trust portal is standalone and must not be iframable by attackers")
	assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))
	assert.Empty(t, resp.Header.Get("Strict-Transport-Security"),
		"plaintext requests must never receive HSTS — a sticky header on localhost is a self-inflicted dev outage")
}

func TestSecurityHeaders_HSTSSetOnDirectTLSConnection(t *testing.T) {
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		HSTSMaxAge: 30 * 24 * time.Hour,
	})
	srv := httptest.NewTLSServer(mw(ok()))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	hsts := resp.Header.Get("Strict-Transport-Security")
	assert.Contains(t, hsts, "max-age=2592000",
		"max-age must equal the configured HSTSMaxAge in seconds — 30 days = 2592000")
	assert.Contains(t, hsts, "includeSubDomains")
}

func TestSecurityHeaders_HSTSSetWhenXForwardedProtoIsHTTPS(t *testing.T) {
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	mw(ok()).ServeHTTP(rec, req)

	assert.NotEmpty(t, rec.Header().Get("Strict-Transport-Security"),
		"requests forwarded by an HTTPS-terminating proxy must still get HSTS — the browser saw HTTPS, that's what matters")
}

func TestSecurityHeaders_HSTSNotSetWhenXForwardedProtoIsHTTP(t *testing.T) {
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	rec := httptest.NewRecorder()
	mw(ok()).ServeHTTP(rec, req)
	assert.Empty(t, rec.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_HSTSReadsFirstTokenOfChain(t *testing.T) {
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Forwarded-Proto", "https, http")
	rec := httptest.NewRecorder()
	mw(ok()).ServeHTTP(rec, req)
	assert.NotEmpty(t, rec.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_PreflightOPTIONSPassesThroughUntouched(t *testing.T) {
	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})

	req := httptest.NewRequest("OPTIONS", "/x", nil)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	assert.True(t, innerCalled, "preflight must reach the inner CORS handler")
	assert.Empty(t, rec.Header().Get("X-Content-Type-Options"),
		"preflight responses must NOT be polluted with security headers — CORS owns the response shape there")
	assert.Empty(t, rec.Header().Get("X-Frame-Options"))
}

func TestSecurityHeaders_NonPreflightOPTIONSStillGetsHeaders(t *testing.T) {
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})
	req := httptest.NewRequest("OPTIONS", "/x", nil)
	rec := httptest.NewRecorder()
	mw(ok()).ServeHTTP(rec, req)
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
}

func TestSecurityHeaders_ConfigOverridesAreHonoured(t *testing.T) {
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		FrameOptions:   "SAMEORIGIN",
		ReferrerPolicy: "strict-origin-when-cross-origin",
	})
	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	mw(ok()).ServeHTTP(rec, req)
	assert.Equal(t, "SAMEORIGIN", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", rec.Header().Get("Referrer-Policy"))
}

func TestSecurityHeaders_DefaultsMatchProductionExpectations(t *testing.T) {
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})
	req := httptest.NewRequest("GET", "/x", nil)
	req.TLS = &tls.ConnectionState{HandshakeComplete: true}
	rec := httptest.NewRecorder()
	mw(ok()).ServeHTTP(rec, req)
	hsts := rec.Header().Get("Strict-Transport-Security")
	assert.Equal(t, "max-age=63072000; includeSubDomains", hsts)
}
