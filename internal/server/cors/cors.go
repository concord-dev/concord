// Package cors handles cross-origin browser requests for the Concord API.
//
// What it does, in browser terms:
//
//   - A browser running JS at https://app.concord.io tries to call
//     https://api.concord.io/v1/orgs/.... Because it's cross-origin AND
//     the request carries Authorization, the browser fires a CORS
//     "preflight" OPTIONS request first, asking the server what it allows.
//   - The server must answer with Access-Control-Allow-Origin (matching
//     the request's Origin exactly), Allow-Methods, Allow-Headers, and
//     Allow-Credentials: true. Without these the browser blocks the real
//     request.
//   - For the actual call (after preflight), the server adds the same
//     Allow-Origin + Allow-Credentials headers; the browser exposes the
//     response to JS.
//
// What it does NOT do:
//
//   - Block requests that lack a matching Origin. CORS is a browser policy;
//     server-to-server callers (curl, the agent, CI) never send Origin and
//     don't need CORS headers at all. We pass those through unchanged.
//   - Wildcard subdomain matching. Operators list the exact origins they
//     trust. Authorization-bearing APIs cannot use `*` for Allow-Origin
//     when Allow-Credentials is true (the spec forbids it), so wildcards
//     aren't useful for our threat model.
//   - Validate the Host header. That's a separate concern (host filtering
//     belongs upstream of the application).
package cors

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config controls which origins may call the API from a browser.
//
// AllowedOrigins must be exact, case-sensitive matches against the
// request's Origin header (scheme + host + port — RFC 6454). Empty means
// CORS is effectively disabled: no Access-Control-* headers are added and
// preflights pass through.
type Config struct {
	AllowedOrigins []string
	AllowedMethods []string      // defaults below
	AllowedHeaders []string      // defaults below
	ExposedHeaders []string      // defaults below
	MaxAge         time.Duration // defaults to 10 minutes
}

// defaults applies fallbacks for any field the caller left zero. Kept as a
// method so the same logic runs in production and in tests that construct
// Config directly.
func (c *Config) defaults() {
	if len(c.AllowedMethods) == 0 {
		c.AllowedMethods = []string{
			http.MethodGet, http.MethodHead, http.MethodPost,
			http.MethodPut, http.MethodDelete, http.MethodOptions,
		}
	}
	if len(c.AllowedHeaders) == 0 {
		c.AllowedHeaders = []string{
			"Authorization", "Content-Type", "Accept",
			"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host",
		}
	}
	if len(c.ExposedHeaders) == 0 {
		// `Location` is set on 201/202 responses (run created, etc.); JS
		// needs to read it to follow up.
		c.ExposedHeaders = []string{"Location", "Content-Type"}
	}
	if c.MaxAge <= 0 {
		c.MaxAge = 10 * time.Minute
	}
}

// New returns the CORS middleware. When AllowedOrigins is empty the
// returned middleware is a no-op: callers without browsers (curl, agents,
// CI) keep working unchanged.
//
// Mount it INSIDE the logging middleware so preflight 204s still show up
// in the access log.
func New(cfg Config) func(http.Handler) http.Handler {
	cfg.defaults()

	// Pre-compute the static header values once — they don't depend on the
	// request and recomputing per-request is wasted CPU at high RPS.
	allowedMethods := strings.Join(cfg.AllowedMethods, ", ")
	allowedHeaders := strings.Join(cfg.AllowedHeaders, ", ")
	exposedHeaders := strings.Join(cfg.ExposedHeaders, ", ")
	maxAge := strconv.Itoa(int(cfg.MaxAge.Seconds()))
	allowed := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowed[o] = struct{}{}
	}
	enabled := len(allowed) > 0

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")
			matched := origin != ""
			if matched {
				if _, ok := allowed[origin]; !ok {
					matched = false
				}
			}

			// Every response that *could* vary on Origin must say so or
			// caches will return the wrong answer cross-origin. Setting
			// Vary even when origin is unmatched is the safe default.
			w.Header().Add("Vary", "Origin")

			if matched {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				// We always send Authorization → Allow-Credentials must be
				// true, which means Allow-Origin must echo the exact origin
				// (the spec forbids `*` in this combination).
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Expose-Headers", exposedHeaders)
			}

			// Preflight: short-circuit. We answer 204 with the policy and
			// never invoke the inner handler, so the mux's lack of OPTIONS
			// routes doesn't 405 the request.
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				if matched {
					h := w.Header()
					h.Set("Access-Control-Allow-Methods", allowedMethods)
					// Echo the requested headers verbatim when present —
					// some frameworks send headers we don't list explicitly
					// (e.g. Sentry's sentry-trace). The list we configured
					// is the *union of common* headers; the spec allows us
					// to be more permissive in the preflight response.
					if reqH := r.Header.Get("Access-Control-Request-Headers"); reqH != "" {
						h.Set("Access-Control-Allow-Headers", reqH)
					} else {
						h.Set("Access-Control-Allow-Headers", allowedHeaders)
					}
					h.Set("Access-Control-Max-Age", maxAge)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
