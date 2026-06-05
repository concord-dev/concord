package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/concord-dev/concord/internal/logx"
)

const RequestIDHeader = "X-Request-ID"

const requestIDMaxLen = 128

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
