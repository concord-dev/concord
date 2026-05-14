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

func repoControlsDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../../controls")
	require.NoError(t, err)
	return abs
}

// openStore opens a Store against the configured Postgres or skips.
func openStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = defaultTestDSN
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := store.Open(ctx, dsn, store.PoolOptions{MaxConns: 4, MinConns: 1})
	if err != nil {
		t.Skipf("skipping: Postgres not reachable at %s (run `docker compose up -d postgres`): %v", dsn, err)
	}
	require.NoError(t, s.Migrate(ctx))
	t.Cleanup(s.Close)
	return s
}

type harness struct {
	srv        *httptest.Server
	c          *server.Concord
	st         *store.Store
	org        store.Organization
	tokenPlain string
}

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

	org, err := st.CreateOrganization(context.Background(), "Test Org", "test-"+uuid.NewString()[:8])
	require.NoError(t, err)
	_, plain, err := st.CreateToken(context.Background(), org.ID, "test", nil)
	require.NoError(t, err)

	return &harness{srv: ts, c: c, st: st, org: org, tokenPlain: plain}
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

func TestOrgRoutes_RequireBearerToken(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/v1/frameworks", "/v1/controls", "/v1/runs", "/v1/me"} {
		resp, body := h.do(t, "GET", p, "", "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, p)
		assert.Contains(t, string(body), "missing Authorization")
	}
}

func TestOrgRoutes_RejectInvalidToken(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/v1/frameworks", "", "concord_bogus")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(body), "invalid token")
}

func TestAdminRoutes_RejectTenantToken(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/admin/v1/orgs", "", h.tokenPlain)
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

	req, _ := http.NewRequest("GET", ts.URL+"/admin/v1/orgs", nil)
	req.Header.Set("Authorization", "Bearer anything")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// --- Admin: orgs + users + memberships ---

func TestAdmin_CreateOrgAndToken_HappyPath(t *testing.T) {
	h := newHarness(t)

	slug := "admin-flow-" + uuid.NewString()[:8]
	body := fmt.Sprintf(`{"name":"Admin Flow","slug":%q}`, slug)
	resp, raw := h.do(t, "POST", "/admin/v1/orgs", body, testAdminToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	var org store.Organization
	require.NoError(t, json.Unmarshal(raw, &org))
	assert.Equal(t, slug, org.Slug)

	resp2, raw2 := h.do(t, "POST", "/admin/v1/orgs/"+slug+"/tokens", `{"name":"ci"}`, testAdminToken)
	require.Equal(t, http.StatusCreated, resp2.StatusCode, string(raw2))

	var tok struct {
		Token string `json:"token"`
		ID    string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(raw2, &tok))
	assert.True(t, strings.HasPrefix(tok.Token, "concord_"))

	// The minted token must now work against /v1/me — and report the org.
	resp3, raw3 := h.do(t, "GET", "/v1/me", "", tok.Token)
	require.Equal(t, http.StatusOK, resp3.StatusCode)
	var me struct {
		Organization store.Organization `json:"organization"`
	}
	require.NoError(t, json.Unmarshal(raw3, &me))
	assert.Equal(t, slug, me.Organization.Slug)

	// Delete the token; subsequent use must 401.
	respDel, _ := h.do(t, "DELETE", "/admin/v1/orgs/"+slug+"/tokens/"+tok.ID, "", testAdminToken)
	assert.Equal(t, http.StatusNoContent, respDel.StatusCode)
	respDeleted, _ := h.do(t, "GET", "/v1/me", "", tok.Token)
	assert.Equal(t, http.StatusUnauthorized, respDeleted.StatusCode)
}

func TestAdmin_CreateOrg_DuplicateSlugConflicts(t *testing.T) {
	h := newHarness(t)
	slug := "dup-" + uuid.NewString()[:8]
	body := fmt.Sprintf(`{"name":"A","slug":%q}`, slug)
	resp, _ := h.do(t, "POST", "/admin/v1/orgs", body, testAdminToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp2, _ := h.do(t, "POST", "/admin/v1/orgs", body, testAdminToken)
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)
}

func TestAdmin_CreateTokenForUnknownOrgIs404(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "POST", "/admin/v1/orgs/nope/tokens", `{"name":"x"}`, testAdminToken)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, string(body), "no organization")
}

func TestAdmin_CreateUser_RoundTrip(t *testing.T) {
	h := newHarness(t)
	email := fmt.Sprintf("alice+%s@example.com", uuid.NewString()[:8])
	resp, raw := h.do(t, "POST", "/admin/v1/users",
		fmt.Sprintf(`{"email":%q,"name":"Alice"}`, email), testAdminToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	var u store.User
	require.NoError(t, json.Unmarshal(raw, &u))
	assert.Equal(t, email, u.Email)

	// List users includes Alice.
	respL, rawL := h.do(t, "GET", "/admin/v1/users", "", testAdminToken)
	require.Equal(t, http.StatusOK, respL.StatusCode)
	var users []store.User
	require.NoError(t, json.Unmarshal(rawL, &users))
	found := false
	for _, x := range users {
		if x.Email == email {
			found = true
		}
	}
	assert.True(t, found, "Alice must appear in /admin/v1/users")
}

func TestAdmin_AddMember_ByEmail_AndList(t *testing.T) {
	h := newHarness(t)

	// Create user via API.
	email := fmt.Sprintf("bob+%s@example.com", uuid.NewString()[:8])
	respU, _ := h.do(t, "POST", "/admin/v1/users",
		fmt.Sprintf(`{"email":%q,"name":"Bob"}`, email), testAdminToken)
	require.Equal(t, http.StatusCreated, respU.StatusCode)

	// Attach to harness's org as admin.
	body := fmt.Sprintf(`{"email":%q,"role":"admin"}`, email)
	resp, raw := h.do(t, "POST", "/admin/v1/orgs/"+h.org.Slug+"/members", body, testAdminToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	// List members.
	respL, rawL := h.do(t, "GET", "/admin/v1/orgs/"+h.org.Slug+"/members", "", testAdminToken)
	require.Equal(t, http.StatusOK, respL.StatusCode)
	var members []store.OrgMember
	require.NoError(t, json.Unmarshal(rawL, &members))
	require.Len(t, members, 1)
	assert.Equal(t, email, members[0].User.Email)
	assert.Equal(t, store.RoleAdmin, members[0].Role)
}

func TestAdmin_AddMember_InvalidRoleRejected(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "POST", "/admin/v1/orgs/"+h.org.Slug+"/members",
		`{"email":"x@example.com","role":"superuser"}`, testAdminToken)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "owner|admin|member|viewer")
}

func TestAdmin_RemoveMember(t *testing.T) {
	h := newHarness(t)
	u, err := h.st.CreateUser(context.Background(), uniqueEmail("rm"), "Rm")
	require.NoError(t, err)
	_, err = h.st.AddMember(context.Background(), u.ID, h.org.ID, store.RoleMember)
	require.NoError(t, err)

	resp, _ := h.do(t, "DELETE",
		"/admin/v1/orgs/"+h.org.Slug+"/members/"+u.ID.String(), "", testAdminToken)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Removing twice returns 404.
	resp2, _ := h.do(t, "DELETE",
		"/admin/v1/orgs/"+h.org.Slug+"/members/"+u.ID.String(), "", testAdminToken)
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

func TestAdmin_BadJSONReturns400(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, "POST", "/admin/v1/orgs", `{not json}`, testAdminToken)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- Org API ---

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
		RunID   string `json:"run_id"`
		Status  string `json:"status"`
		PollURL string `json:"poll_url"`
	}
	require.NoError(t, json.Unmarshal(body, &enq))
	assert.NotEmpty(t, enq.RunID)
	assert.Equal(t, "pending", enq.Status)

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
	require.Equal(t, "succeeded", detail["status"])

	resp3, body3 := h.do(t, "GET", "/v1/findings", "", h.tokenPlain)
	require.Equal(t, http.StatusOK, resp3.StatusCode)
	var second struct {
		Findings []apiv1.Finding `json:"findings"`
		RunID    string          `json:"run_id"`
	}
	require.NoError(t, json.Unmarshal(body3, &second))
	assert.Equal(t, enq.RunID, second.RunID)
	assert.Equal(t, len(h.c.Controls), len(second.Findings))

	resp4, body4 := h.do(t, "GET", "/v1/runs", "", h.tokenPlain)
	require.Equal(t, http.StatusOK, resp4.StatusCode)
	var runs []map[string]any
	require.NoError(t, json.Unmarshal(body4, &runs))
	require.NotEmpty(t, runs)
	assert.Equal(t, "succeeded", runs[0]["status"])
}

func TestRuns_CannotCrossOrg(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "POST", "/v1/check", "", h.tokenPlain)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	var first struct {
		RunID string `json:"run_id"`
	}
	require.NoError(t, json.Unmarshal(body, &first))

	other, _ := h.st.CreateOrganization(context.Background(), "Other", "other-"+uuid.NewString()[:8])
	_, otherTok, _ := h.st.CreateToken(context.Background(), other.ID, "ci", nil)

	resp2, _ := h.do(t, "GET", "/v1/runs/"+first.RunID, "", otherTok)
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode,
		"org B must NOT see org A's runs")
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

func TestBearer_CaseInsensitive(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET", h.srv.URL+"/v1/frameworks", bytes.NewReader(nil))
	req.Header.Set("Authorization", "bearer "+h.tokenPlain)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestNewConcord_RequiresStore(t *testing.T) {
	_, err := server.NewConcord(server.Options{
		ControlsDir: repoControlsDir(t),
		ConfigPath:  filepath.Join(t.TempDir(), "x.yaml"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Store is required")
}

// --- SSE ---

func TestEvents_StreamsRunLifecycle(t *testing.T) {
	h := newHarness(t)

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

	// Wait for the bus to register the subscriber before we publish.
	require.Eventually(t, func() bool {
		return h.c.Bus().SubscriberCount(h.org.ID) > 0
	}, 2*time.Second, 10*time.Millisecond)

	respCheck, _ := h.do(t, "POST", "/v1/check", "", h.tokenPlain)
	require.Equal(t, http.StatusAccepted, respCheck.StatusCode)

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
			t.Fatalf("timed out; sawStarted=%v sawCompleted=%v", sawStarted, sawCompleted)
		}
	}
	assert.True(t, sawStarted)
}

func TestEvents_RequiresAuth(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, "GET", "/v1/events", "", "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestEvents_NoCrossOrgLeak(t *testing.T) {
	h := newHarness(t)

	reqA, _ := http.NewRequest("GET", h.srv.URL+"/v1/events", nil)
	reqA.Header.Set("Authorization", "Bearer "+h.tokenPlain)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	respA, err := http.DefaultClient.Do(reqA.WithContext(ctxA))
	require.NoError(t, err)
	defer respA.Body.Close()
	require.Eventually(t, func() bool {
		return h.c.Bus().SubscriberCount(h.org.ID) > 0
	}, 2*time.Second, 10*time.Millisecond)

	other, _ := h.st.CreateOrganization(context.Background(), "Other", "other-"+uuid.NewString()[:8])
	_, otherTok, _ := h.st.CreateToken(context.Background(), other.ID, "ci", nil)
	resp, _ := h.do(t, "POST", "/v1/check", "", otherTok)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

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
			t.Fatalf("org A received leaked event %q", f.Event)
		case <-deadline:
			return
		}
	}
}

// --- Worker / queue ---

func TestCheck_QueueFullReturns503(t *testing.T) {
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

	org, _ := st.CreateOrganization(context.Background(), "QFull", "qfull-"+uuid.NewString()[:8])
	_, tok, _ := st.CreateToken(context.Background(), org.ID, "ci", nil)

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

// --- SSE helpers ---

type sseFrame struct {
	Event string
	Data  string
}

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

func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s+%s@example.com", prefix, uuid.NewString()[:8])
}
