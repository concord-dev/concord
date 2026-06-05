package metrics

import (
	"net/http"
	"strconv"
	"time"
)

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

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
