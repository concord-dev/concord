package cors

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AllowedOrigins []string
	AllowedMethods []string      // defaults below
	AllowedHeaders []string      // defaults below
	ExposedHeaders []string      // defaults below
	MaxAge         time.Duration // defaults to 10 minutes
}

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
		c.ExposedHeaders = []string{"Location", "Content-Type"}
	}
	if c.MaxAge <= 0 {
		c.MaxAge = 10 * time.Minute
	}
}

func New(cfg Config) func(http.Handler) http.Handler {
	cfg.defaults()

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

			w.Header().Add("Vary", "Origin")

			if matched {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Expose-Headers", exposedHeaders)
			}

			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				if matched {
					h := w.Header()
					h.Set("Access-Control-Allow-Methods", allowedMethods)
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
