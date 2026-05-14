package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server"
	"github.com/concord-dev/concord/internal/store"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const defaultTestDSN = "postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable"
const testAdminToken = "test-admin-token-fixed"

// repoControlsDir resolves the bundled controls library.
func repoControlsDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../../controls")
	require.NoError(t, err)
	return abs
}

// openStore opens a Store against the configured Postgres or skips. Same
// pattern as internal/store/store_test.go so the suite stays usable on
// developer machines without Docker.
func openStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = defaultTestDSN
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Skipf("skipping: Postgres not reachable at %s (run `docker compose up -d postgres`): %v", dsn, err)
	}
	require.NoError(t, s.Migrate(ctx))
	t.Cleanup(func() { _ = s.Close() })
	return s
}

type harness struct {
	srv       *httptest.Server
	c         *server.Concord
	st        *store.Store
	tenant    store.Tenant
	tokenPlain string
}

// newHarness spins up a server with admin auth wired, creates a fresh tenant
// + token, and returns a ready-to-call client surface.
func newHarness(t *testing.T) *harness {
	t.Helper()
	st := openStore(t)
	c, err := server.NewConcord(server.Options{
		ControlsDir:  repoControlsDir(t),
		ConfigPath:   filepath.Join(t.TempDir(), "missing-concord.yaml"),
		FixturesOnly: true,
		Store:        st,
		AdminToken:   testAdminToken,
		Version:      "test",
	})
	require.NoError(t, err)
	ts := httptest.NewServer(c.Router())
	t.Cleanup(ts.Close)

	tenant, err := st.CreateTenant(context.Background(), "Test Tenant", "test-"+uuid.NewString()[:8])
	require.NoError(t, err)
	_, plain, err := st.CreateToken(context.Background(), tenant.ID, "test")
	require.NoError(t, err)

	return &harness{srv: ts, c: c, st: st, tenant: tenant, tokenPlain: plain}
}

func (h *harness) do(t *testing.T, method, path, body, auth string) (*http.Response, []byte) {
	t.Helper()
	var br io.Reader
	if body != "" {
		br = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, br)
	require.NoError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// --- Public endpoints ---

func TestHealth_NoAuthRequired(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/healthz", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"status":"ok"}`, string(body))
}

func TestVersion_NoAuthRequired(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/version", "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "test", got["version"])
}

// --- Auth ---

func TestTenantRoutes_RequireBearerToken(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/v1/frameworks", "/v1/controls", "/v1/runs"} {
		resp, body := h.do(t, "GET", p, "", "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, p)
		assert.Contains(t, string(body), "missing Authorization")
	}
}

func TestTenantRoutes_RejectInvalidToken(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/v1/frameworks", "", "concord_bogus")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(body), "invalid token")
}

func TestAdminRoutes_RequireAdminToken(t *testing.T) {
	h := newHarness(t)
	// Using the tenant token must be rejected for admin paths.
	resp, body := h.do(t, "GET", "/admin/v1/tenants", "", h.tokenPlain)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(body), "invalid admin token")
}

func TestAdminRoutes_DisabledWhenAdminTokenUnset(t *testing.T) {
	st := openStore(t)
	c, err := server.NewConcord(server.Options{
		ControlsDir: repoControlsDir(t), ConfigPath: filepath.Join(t.TempDir(), "x.yaml"),
		FixturesOnly: true, Store: st, AdminToken: "", Version: "test",
	})
	require.NoError(t, err)
	ts := httptest.NewServer(c.Router())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest("GET", ts.URL+"/admin/v1/tenants", nil)
	req.Header.Set("Authorization", "Bearer anything")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// --- Admin CRUD ---

func TestAdmin_CreateTenantAndToken_HappyPath(t *testing.T) {
	h := newHarness(t)

	slug := "admin-flow-" + uuid.NewString()[:8]
	body := fmt.Sprintf(`{"name":"Admin Flow","slug":%q}`, slug)
	resp, raw := h.do(t, "POST", "/admin/v1/tenants", body, testAdminToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	var tenant store.Tenant
	require.NoError(t, json.Unmarshal(raw, &tenant))
	assert.Equal(t, slug, tenant.Slug)

	// Mint a token for the new tenant.
	resp2, raw2 := h.do(t, "POST", "/admin/v1/tenants/"+slug+"/tokens", `{"name":"ci"}`, testAdminToken)
	require.Equal(t, http.StatusCreated, resp2.StatusCode, string(raw2))

	var tok struct {
		Token string `json:"token"`
		ID    string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(raw2, &tok))
	assert.True(t, strings.HasPrefix(tok.Token, "concord_"))

	// The plain token must now work against /v1/*.
	resp3, _ := h.do(t, "GET", "/v1/frameworks", "", tok.Token)
	assert.Equal(t, http.StatusOK, resp3.StatusCode)

	// Listing tokens must include the new one.
	respL, rawL := h.do(t, "GET", "/admin/v1/tenants/"+slug+"/tokens", "", testAdminToken)
	require.Equal(t, http.StatusOK, respL.StatusCode)
	var toks []store.Token
	require.NoError(t, json.Unmarshal(rawL, &toks))
	assert.Len(t, toks, 1)
	assert.Equal(t, "ci", toks[0].Name)

	// Delete the token; subsequent use must 401.
	resp4, _ := h.do(t, "DELETE", "/admin/v1/tenants/"+slug+"/tokens/"+tok.ID, "", testAdminToken)
	assert.Equal(t, http.StatusNoContent, resp4.StatusCode)
	resp5, _ := h.do(t, "GET", "/v1/frameworks", "", tok.Token)
	assert.Equal(t, http.StatusUnauthorized, resp5.StatusCode)
}

func TestAdmin_CreateTenant_DuplicateSlugConflicts(t *testing.T) {
	h := newHarness(t)
	slug := "dup-" + uuid.NewString()[:8]
	body := fmt.Sprintf(`{"name":"A","slug":%q}`, slug)
	resp, _ := h.do(t, "POST", "/admin/v1/tenants", body, testAdminToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp2, _ := h.do(t, "POST", "/admin/v1/tenants", body, testAdminToken)
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)
}

func TestAdmin_CreateTokenForUnknownTenantIs404(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "POST", "/admin/v1/tenants/nope/tokens", `{"name":"x"}`, testAdminToken)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, string(body), "no tenant")
}

// --- Tenant API ---

func TestControls_ListAndFilter(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/v1/controls?framework=nist-800-53", "", h.tokenPlain)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got []apiv1.Control
	require.NoError(t, json.Unmarshal(body, &got))
	require.NotEmpty(t, got)
	for _, c := range got {
		assert.Equal(t, "nist-800-53", c.Metadata.Framework)
	}
}

func TestControl_GetByID_CaseInsensitive(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, "GET", "/v1/controls/soc2-cc8.1", "", h.tokenPlain)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestCheck_ReturnsAcceptedThenPollSucceeds(t *testing.T) {
	h := newHarness(t)

	resp, body := h.do(t, "POST", "/v1/check", "", h.tokenPlain)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, string(body))
	assert.Equal(t, "/v1/runs/", resp.Header.Get("Location")[:9])

	var enq struct {
		RunID    string `json:"run_id"`
		Status   string `json:"status"`
		PollURL  string `json:"poll_url"`
	}
	require.NoError(t, json.Unmarshal(body, &enq))
	assert.NotEmpty(t, enq.RunID)
	assert.Equal(t, "pending", enq.Status)

	// Poll the run until it completes.
	var detail map[string]any
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp2, body2 := h.do(t, "GET", "/v1/runs/"+enq.RunID, "", h.tokenPlain)
		require.Equal(t, http.StatusOK, resp2.StatusCode)
		require.NoError(t, json.Unmarshal(body2, &detail))
		if detail["status"] != "pending" && detail["status"] != "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Equal(t, "succeeded", detail["status"], "run never succeeded within 15s")

	// /v1/findings now returns the persisted run's data.
	resp3, body3 := h.do(t, "GET", "/v1/findings", "", h.tokenPlain)
	require.Equal(t, http.StatusOK, resp3.StatusCode)
	var second struct {
		Findings []apiv1.Finding `json:"findings"`
		RunID    string          `json:"run_id"`
	}
	require.NoError(t, json.Unmarshal(body3, &second))
	assert.Equal(t, enq.RunID, second.RunID)
	assert.Equal(t, len(h.c.Controls), len(second.Findings))

	// /v1/runs lists the run as succeeded.
	resp4, body4 := h.do(t, "GET", "/v1/runs", "", h.tokenPlain)
	require.Equal(t, http.StatusOK, resp4.StatusCode)
	var runs []map[string]any
	require.NoError(t, json.Unmarshal(body4, &runs))
	require.NotEmpty(t, runs)
	assert.Equal(t, "succeeded", runs[0]["status"])
}

func TestRuns_CannotCrossTenant(t *testing.T) {
	h := newHarness(t)
	// h's tenant kicks off one check.
	resp, body := h.do(t, "POST", "/v1/check", "", h.tokenPlain)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	var first struct{ RunID string `json:"run_id"` }
	require.NoError(t, json.Unmarshal(body, &first))

	// Create a second tenant + token, and try to fetch the first tenant's run.
	other, err := h.st.CreateTenant(context.Background(), "Other", "other-"+uuid.NewString()[:8])
	require.NoError(t, err)
	_, otherTok, err := h.st.CreateToken(context.Background(), other.ID, "ci")
	require.NoError(t, err)

	resp2, _ := h.do(t, "GET", "/v1/runs/"+first.RunID, "", otherTok)
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode,
		"tenant B must NOT see tenant A's runs")
}

func TestFindings_BeforeAnyCheckReturns404(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/v1/findings", "", h.tokenPlain)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, string(body), "POST /v1/check first")
}

func TestGetRun_InvalidIDReturns400(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, "GET", "/v1/runs/not-a-uuid", "", h.tokenPlain)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAdmin_BadJSONReturns400(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, "POST", "/admin/v1/tenants", `{not json}`, testAdminToken)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// Quick guard: the test fixture for Bearer parsing must accept "bearer "
// case-insensitively, matching RFC 6750.
func TestBearer_CaseInsensitive(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET", h.srv.URL+"/v1/frameworks", bytes.NewReader(nil))
	req.Header.Set("Authorization", "bearer "+h.tokenPlain)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestEvents_StreamsRunLifecycle(t *testing.T) {
	h := newHarness(t)

	// Subscribe first so we don't miss the run.started event.
	req, _ := http.NewRequest("GET", h.srv.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+h.tokenPlain)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	// Give the subscription a beat to register on the bus before we publish.
	require.Eventually(t, func() bool {
		return h.c.Bus().SubscriberCount(h.tenant.ID) > 0
	}, 2*time.Second, 10*time.Millisecond)

	// Kick off a run via the HTTP API.
	respCheck, _ := h.do(t, "POST", "/v1/check", "", h.tokenPlain)
	require.Equal(t, http.StatusAccepted, respCheck.StatusCode)

	// Stream the SSE response onto a channel so the test can deadline reads.
	// The reader goroutine exits when the response body closes (cancel()).
	frames := make(chan sseFrame, 32)
	go func() {
		defer close(frames)
		readSSEFrames(resp.Body, frames)
	}()

	var sawStarted, sawCompleted bool
	deadline := time.After(15 * time.Second)
loop:
	for !sawCompleted {
		select {
		case f, ok := <-frames:
			if !ok {
				break loop
			}
			switch f.Event {
			case "run.started":
				sawStarted = true
			case "run.completed":
				sawCompleted = true
				assert.Contains(t, f.Data, "run.completed")
				assert.Contains(t, f.Data, "succeeded")
			}
		case <-deadline:
			t.Fatalf("timed out waiting for SSE frames; sawStarted=%v sawCompleted=%v", sawStarted, sawCompleted)
		}
	}
	assert.True(t, sawStarted, "run.started should arrive before run.completed")
}

func TestEvents_RequiresAuth(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, "GET", "/v1/events", "", "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestEvents_NoCrossTenantLeak(t *testing.T) {
	h := newHarness(t)

	// Subscribe as tenant A.
	reqA, _ := http.NewRequest("GET", h.srv.URL+"/v1/events", nil)
	reqA.Header.Set("Authorization", "Bearer "+h.tokenPlain)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	respA, err := http.DefaultClient.Do(reqA.WithContext(ctxA))
	require.NoError(t, err)
	defer respA.Body.Close()
	require.Eventually(t, func() bool {
		return h.c.Bus().SubscriberCount(h.tenant.ID) > 0
	}, 2*time.Second, 10*time.Millisecond)

	// Create tenant B and have it run a check.
	other, _ := h.st.CreateTenant(context.Background(), "Other", "other-"+uuid.NewString()[:8])
	_, otherTok, _ := h.st.CreateToken(context.Background(), other.ID, "ci")
	resp, _ := h.do(t, "POST", "/v1/check", "", otherTok)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	// Tenant A's stream must NOT receive tenant B's events. Drain for 1s;
	// if any frame arrives on A's stream during that window, fail.
	frames := make(chan sseFrame, 16)
	go func() {
		defer close(frames)
		readSSEFrames(respA.Body, frames)
	}()
	deadline := time.After(time.Second)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				return
			}
			t.Fatalf("tenant A received leaked event %q (data=%q)", f.Event, f.Data)
		case <-deadline:
			// expected — nothing leaked
			return
		}
	}
}

// sseFrame is one parsed Server-Sent Event frame.
type sseFrame struct {
	Event string
	Data  string
}

// readSSEFrames parses an io.Reader as a stream of SSE frames and forwards
// each non-comment frame on out. Comment-only frames (prelude, heartbeats) are
// dropped. The function returns when the reader closes.
func readSSEFrames(r io.Reader, out chan<- sseFrame) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				idx := strings.Index(string(buf), "\n\n")
				if idx < 0 {
					break
				}
				raw := string(buf[:idx])
				buf = buf[idx+2:]
				var f sseFrame
				for _, line := range strings.Split(raw, "\n") {
					switch {
					case strings.HasPrefix(line, "event: "):
						f.Event = strings.TrimPrefix(line, "event: ")
					case strings.HasPrefix(line, "data: "):
						f.Data = strings.TrimPrefix(line, "data: ")
					}
				}
				if f.Event != "" {
					out <- f
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func TestCheck_QueueFullReturns503(t *testing.T) {
	// Build a server with a 0-capacity queue and a single worker so the second
	// concurrent enqueue is guaranteed to fail.
	st := openStore(t)
	c, err := server.NewConcord(server.Options{
		ControlsDir:  repoControlsDir(t),
		ConfigPath:   filepath.Join(t.TempDir(), "x.yaml"),
		FixturesOnly: true,
		Store:        st,
		AdminToken:   testAdminToken,
		Version:      "test",
		Worker:       server.WorkerOpts{PoolSize: 1, QueueSize: 1},
	})
	require.NoError(t, err)
	ts := httptest.NewServer(c.Router())
	t.Cleanup(ts.Close)

	tenant, _ := st.CreateTenant(context.Background(), "QFull", "qfull-"+uuid.NewString()[:8])
	_, tok, _ := st.CreateToken(context.Background(), tenant.ID, "ci")

	// Fire enough concurrent requests that one is guaranteed to hit the
	// queue-full path. With pool=1 + queue=1, the 3rd in-flight enqueue must 503.
	statuses := make(chan int, 5)
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", ts.URL+"/v1/check", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			_ = resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(statuses)
	sawQueueFull := false
	for s := range statuses {
		if s == http.StatusServiceUnavailable {
			sawQueueFull = true
		}
	}
	assert.True(t, sawQueueFull, "with pool=1 + queue=1 some of the 5 concurrent requests must 503")
}

func TestNewConcord_RequiresStore(t *testing.T) {
	_, err := server.NewConcord(server.Options{
		ControlsDir: repoControlsDir(t),
		ConfigPath:  filepath.Join(t.TempDir(), "x.yaml"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Store is required")
}
