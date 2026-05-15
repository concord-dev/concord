package metrics

import (
	"net/http"
	"strconv"
	"time"
)

// Middleware returns an HTTP middleware that records request volume, latency,
// and inflight count. Routes are labeled by `r.Pattern` (Go 1.22+ ServeMux
// match), which keeps cardinality bounded — a path like
// /v1/orgs/acme/runs/abc-123 records under the pattern
// /v1/orgs/{slug}/runs/{id}. Unmatched routes (mostly 404s) share the
// `unmatched` label so an attack hitting random URLs can't blow up cardinality.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.HTTPInflight.Inc()
		defer m.HTTPInflight.Dec()

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		dur := time.Since(start).Seconds()

		pattern := r.Pattern
		if pattern == "" {
			pattern = "unmatched"
		}
		m.HTTPRequestsTotal.
			WithLabelValues(r.Method, pattern, strconv.Itoa(rec.status)).
			Inc()
		m.HTTPRequestDuration.
			WithLabelValues(r.Method, pattern).
			Observe(dur)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

// Flush keeps the SSE handler's w.(http.Flusher) assertion happy when this
// middleware sits in the chain.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
