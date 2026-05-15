package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/server/middleware"
)

// captureHandler stashes the request-scoped ID + the value the middleware
// echoed in the response, so each test can assert on both.
type captureHandler struct {
	gotCtxID string
}

func (c *captureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.gotCtxID = logx.RequestID(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func TestRequestID_GeneratesWhenMissing(t *testing.T) {
	cap := &captureHandler{}
	srv := httptest.NewServer(middleware.RequestID(cap))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest("GET", srv.URL+"/x", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	echoed := resp.Header.Get(middleware.RequestIDHeader)
	assert.NotEmpty(t, echoed, "must mint an ID when none was supplied")
	assert.Len(t, echoed, 32, "minted IDs are 16 random bytes hex-encoded")
	assert.Equal(t, echoed, cap.gotCtxID,
		"the same ID must be visible in handler context and the response header")
}

func TestRequestID_HonoursInboundValue(t *testing.T) {
	cap := &captureHandler{}
	srv := httptest.NewServer(middleware.RequestID(cap))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest("GET", srv.URL+"/x", nil)
	req.Header.Set(middleware.RequestIDHeader, "trace-from-caller-42")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, "trace-from-caller-42", resp.Header.Get(middleware.RequestIDHeader))
	assert.Equal(t, "trace-from-caller-42", cap.gotCtxID)
}

func TestRequestID_RejectsHostileInbound(t *testing.T) {
	// Control characters or absurdly long values must be replaced — we don't
	// want an upstream attacker injecting newlines into our log pipeline.
	// Drive the middleware directly because Go's HTTP client/server stack
	// pre-validates header bytes before our code ever sees them, which would
	// hide the rejection we're trying to assert here.
	cases := map[string]string{
		"control char": "abc\x00def",
		"too long":     strings.Repeat("x", 200),
		"empty":        "",
	}
	for name, hostile := range cases {
		t.Run(name, func(t *testing.T) {
			cap := &captureHandler{}
			req := httptest.NewRequest("GET", "/x", nil)
			req.Header.Set(middleware.RequestIDHeader, hostile)
			rec := httptest.NewRecorder()
			middleware.RequestID(cap).ServeHTTP(rec, req)

			echoed := rec.Header().Get(middleware.RequestIDHeader)
			assert.NotEqual(t, hostile, echoed, "hostile value must be replaced")
			assert.Len(t, echoed, 32)
		})
	}
}
