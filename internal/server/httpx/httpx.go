// Package httpx provides shared HTTP helpers used by every handler subpackage:
// JSON/Error response writers and a logging middleware.
package httpx

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
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

// Logging is the minimal request logger middleware: method, path, status, duration.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		fmt.Fprintf(os.Stderr, "%s %s %d %s\n",
			r.Method, r.URL.Path, rw.status, time.Since(start).Round(time.Millisecond))
	})
}

// statusRecorder is a thin wrapper that remembers the status code so the
// logging middleware can read it after the handler returns.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush delegates so the SSE handler's w.(http.Flusher) assertion still passes
// after Logging wraps the response writer.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
