package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/concord-dev/concord/internal/logx"
)

// RequestIDHeader is the canonical header carrying the trace correlation ID.
const RequestIDHeader = "X-Request-ID"

const requestIDMaxLen = 128

// RequestID returns a middleware that ensures every request has a request ID
// attached to its context (so logx.FromContext can surface it) and echoed in
// the response header. An inbound X-Request-ID is honored when it passes a
// minimal sanity check, otherwise a fresh 128-bit hex ID is generated. The
// sanity check exists so a hostile upstream can't inject control characters
// or unbounded strings into our log pipeline.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if !validRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		ctx := logx.WithRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func validRequestID(id string) bool {
	if id == "" || len(id) > requestIDMaxLen {
		return false
	}
	for _, c := range id {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}
