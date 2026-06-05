package middleware

import (
	"net/http"
	"strconv"
	"time"
)

type SecurityHeadersConfig struct {
	HSTSMaxAge time.Duration

	HSTSIncludeSubdomains bool

	FrameOptions string

	ReferrerPolicy string
}

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
	c.HSTSIncludeSubdomains = true
	return c
}

func SecurityHeaders(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	resolved := secHeaderDefaults(cfg)
	hstsValue := "max-age=" + strconv.FormatInt(int64(resolved.HSTSMaxAge.Seconds()), 10)
	if resolved.HSTSIncludeSubdomains {
		hstsValue += "; includeSubDomains"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
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

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		if i := indexByte(proto, ','); i > 0 {
			proto = proto[:i]
		}
		return equalFoldASCII(proto, "https")
	}
	return false
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

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
