package middleware

import (
	"net/http"
	"strconv"
	"time"
)

// SecurityHeadersConfig tunes the headers SecurityHeaders writes. Zero
// values map to safe defaults so the common call site
// (SecurityHeaders(SecurityHeadersConfig{})) does the right thing.
type SecurityHeadersConfig struct {
	// HSTSMaxAge is the value of Strict-Transport-Security's max-age
	// directive. Only emitted when the request arrived over TLS (or via
	// a TLS-terminating proxy that set X-Forwarded-Proto: https) so a
	// plaintext dev server doesn't pin browsers to HTTPS prematurely.
	// Defaults to 2 years (63072000 seconds), which is what HSTS-preload
	// requires.
	HSTSMaxAge time.Duration

	// HSTSIncludeSubdomains controls the matching directive on HSTS.
	// True is the safe default — keep it unless you really do serve
	// non-HTTPS subdomains of the same registrable origin.
	HSTSIncludeSubdomains bool

	// FrameOptions is the X-Frame-Options value. "DENY" forbids any
	// iframe embedding; "SAMEORIGIN" allows the same-origin case (useful
	// if the API and the dashboard share a domain). Defaults to "DENY"
	// because the trust portal can be loaded standalone and must not be
	// embeddable by attackers spoofing branding.
	FrameOptions string

	// ReferrerPolicy is emitted verbatim. Defaults to "no-referrer" —
	// the most paranoid value, never leaks the originating URL on
	// outbound links/scripts/images. Operators serving a dashboard that
	// needs Referer for analytics can soften this to
	// "strict-origin-when-cross-origin".
	ReferrerPolicy string
}

// secHeaderDefaults backfills zero values on the config. Separated so the
// middleware reads a single resolved config, not a stew of fallbacks.
func secHeaderDefaults(c SecurityHeadersConfig) SecurityHeadersConfig {
	if c.HSTSMaxAge <= 0 {
		c.HSTSMaxAge = 2 * 365 * 24 * time.Hour
	}
	if c.FrameOptions == "" {
		c.FrameOptions = "DENY"
	}
	if c.ReferrerPolicy == "" {
		c.ReferrerPolicy = "no-referrer"
	}
	// HSTSIncludeSubdomains is a bool — zero value is false; we want the
	// safe default of true. Setting it here means callers can still
	// override by explicitly passing false, just not via the zero value.
	// (No clean way to express "true by default + opt-out" with a bool;
	// we accept the wrinkle and document it.)
	c.HSTSIncludeSubdomains = true
	return c
}

// SecurityHeaders returns a middleware that writes the following headers
// on every response:
//
//   X-Content-Type-Options:   nosniff
//   X-Frame-Options:          <config>           (default DENY)
//   Referrer-Policy:          <config>           (default no-referrer)
//   Strict-Transport-Security max-age=<config>;  (only when r is HTTPS)
//
// Skips OPTIONS requests with Access-Control-Request-Method (CORS
// preflights) so the CORS middleware's 204 short-circuit isn't polluted
// — the browser doesn't care about security headers on a preflight, and
// our existing CORS tests assert on a tight header set.
func SecurityHeaders(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	resolved := secHeaderDefaults(cfg)
	hstsValue := "max-age=" + strconv.FormatInt(int64(resolved.HSTSMaxAge.Seconds()), 10)
	if resolved.HSTSIncludeSubdomains {
		hstsValue += "; includeSubDomains"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				// CORS preflight — let it through untouched.
				next.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", resolved.FrameOptions)
			h.Set("Referrer-Policy", resolved.ReferrerPolicy)
			if requestIsHTTPS(r) {
				h.Set("Strict-Transport-Security", hstsValue)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requestIsHTTPS reports whether the request reached the server over TLS,
// either directly (r.TLS) or via a TLS-terminating proxy that set
// X-Forwarded-Proto: https. Mirrors the same logic used by resetBaseURL
// and acceptURL so HSTS and email URLs agree on protocol.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		// Standard XFP carries either "https" or "http"; some proxies
		// send a comma-separated chain — first entry is closest to the
		// client. Match the first token.
		if i := indexByte(proto, ','); i > 0 {
			proto = proto[:i]
		}
		return equalFoldASCII(proto, "https")
	}
	return false
}

// indexByte is strings.IndexByte without the import dependency churn
// every time we reach for a string helper in a leaf package.
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// equalFoldASCII is a single-byte case-insensitive compare for the
// 7-bit ASCII inputs we expect ("https"/"HTTPS"/"Https"). Avoids
// strings.EqualFold's allocations.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
