// Package httpx provides shared HTTP helpers used by every handler subpackage:
// JSON/Error response writers and a structured access-log middleware.
package httpx

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/concord-dev/concord/internal/logx"
)

// JSON serializes body as JSON and writes it with the requested status code.
// Falls back to a minimal hand-rolled error envelope if Encode fails so the
// client still sees an error rather than an empty response.
func JSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		_, _ = io.WriteString(w, fmt.Sprintf(`{"error":%q}`, err.Error()))
	}
}

// Error is the standard error response shape: {"error": <msg>}.
func Error(w http.ResponseWriter, code int, msg string) {
	JSON(w, code, map[string]string{"error": msg})
}

// Logging emits one structured access-log record per request. The level is
// chosen by status class: 5xx → error, 4xx → warn, everything else → info.
// Place it ABOVE the request-ID middleware so each line carries request_id.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		dur := time.Since(start)
		level := slog.LevelInfo
		switch {
		case rw.status >= 500:
			level = slog.LevelError
		case rw.status >= 400:
			level = slog.LevelWarn
		}
		logx.FromContext(r.Context()).LogAttrs(r.Context(), level, "http_request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rw.status),
			slog.Int64("duration_ms", dur.Milliseconds()),
			slog.Int("bytes", rw.bytes),
			slog.String("remote", r.RemoteAddr),
		)
	})
}

// statusRecorder is a thin wrapper that remembers the status code and bytes
// written so the logging middleware can read them after the handler returns.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
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

func (s *statusRecorder) Write(p []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	n, err := s.ResponseWriter.Write(p)
	s.bytes += n
	return n, err
}

// Flush delegates so the SSE handler's w.(http.Flusher) assertion still passes
// after Logging wraps the response writer.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
