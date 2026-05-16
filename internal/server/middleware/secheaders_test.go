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

// ok is the trivial inner handler used throughout — every assertion
// below is about the response headers, not the body.
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
	// Plaintext httptest server → HSTS must NOT be set; otherwise we'd
	// pin developers' browsers to HTTPS for localhost forever.
	assert.Empty(t, resp.Header.Get("Strict-Transport-Security"),
		"plaintext requests must never receive HSTS — a sticky header on localhost is a self-inflicted dev outage")
}

func TestSecurityHeaders_HSTSSetOnDirectTLSConnection(t *testing.T) {
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
		HSTSMaxAge: 30 * 24 * time.Hour,
	})
	srv := httptest.NewTLSServer(mw(ok()))
	t.Cleanup(srv.Close)

	// Use the server's own client so the self-signed cert is trusted.
	resp, err := srv.Client().Get(srv.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	hsts := resp.Header.Get("Strict-Transport-Security")
	assert.Contains(t, hsts, "max-age=2592000",
		"max-age must equal the configured HSTSMaxAge in seconds — 30 days = 2592000")
	assert.Contains(t, hsts, "includeSubDomains")
}

func TestSecurityHeaders_HSTSSetWhenXForwardedProtoIsHTTPS(t *testing.T) {
	// Real deploys put a TLS-terminating proxy in front of the Go server.
	// HSTS must trigger off X-Forwarded-Proto: https just like our other
	// "is this request actually HTTPS" code paths.
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
	// Some proxies forward the full XFP chain ("https, http") — the
	// leftmost token is closest to the client, that's what we trust.
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Forwarded-Proto", "https, http")
	rec := httptest.NewRecorder()
	mw(ok()).ServeHTTP(rec, req)
	assert.NotEmpty(t, rec.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_PreflightOPTIONSPassesThroughUntouched(t *testing.T) {
	// CORS preflight: SecurityHeaders must NOT pollute the 204 response.
	// The existing CORS tests assert on a tight header set; adding nosniff
	// etc. there would break them, so we explicitly skip preflights.
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
	// Plain OPTIONS without Access-Control-Request-Method is a regular
	// request (e.g. a health-check tool probing). It MUST still get
	// hardening headers — the preflight skip is a narrow exception.
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})
	req := httptest.NewRequest("OPTIONS", "/x", nil)
	rec := httptest.NewRecorder()
	mw(ok()).ServeHTTP(rec, req)
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
}

func TestSecurityHeaders_ConfigOverridesAreHonoured(t *testing.T) {
	// Operators serving a single-page dashboard from the same origin may
	// want SAMEORIGIN instead of DENY; same idea for a more permissive
	// referrer policy. Confirm the overrides actually plumb through.
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

// TestSecurityHeaders_DefaultsMatchProductionExpectations is a guard rail
// for the boring case — the maintainer rule we want to enforce is "if you
// rename a default to something with worse security properties, you must
// update this test." It's a small price for surfacing accidental
// regressions on the most-used call site.
func TestSecurityHeaders_DefaultsMatchProductionExpectations(t *testing.T) {
	mw := middleware.SecurityHeaders(middleware.SecurityHeadersConfig{})
	req := httptest.NewRequest("GET", "/x", nil)
	req.TLS = &tls.ConnectionState{HandshakeComplete: true}
	rec := httptest.NewRecorder()
	mw(ok()).ServeHTTP(rec, req)
	hsts := rec.Header().Get("Strict-Transport-Security")
	// 2 years in seconds = 63072000. HSTS-preload requires >= 1 year, so
	// keep this floor; if we lower it deliberately, update both the
	// constant and this test.
	assert.Equal(t, "max-age=63072000; includeSubDomains", hsts)
}
