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

func TestCheck_PersistsRunAndIsRetrievable(t *testing.T) {
	h := newHarness(t)

	resp, body := h.do(t, "POST", "/v1/check", "", h.tokenPlain)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	var got struct {
		RunID    string            `json:"run_id"`
		Summary  map[string]int    `json:"summary"`
		Findings []apiv1.Finding   `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.NotEmpty(t, got.RunID)
	assert.Equal(t, len(h.c.Controls), len(got.Findings))
	assert.Equal(t, len(h.c.Controls), got.Summary["pass"])

	// /v1/findings should now return the same data.
	resp2, body2 := h.do(t, "GET", "/v1/findings", "", h.tokenPlain)
	require.Equal(t, http.StatusOK, resp2.StatusCode, string(body2))
	var second struct {
		Findings []apiv1.Finding `json:"findings"`
		RunID    string          `json:"run_id"`
	}
	require.NoError(t, json.Unmarshal(body2, &second))
	assert.Equal(t, got.RunID, second.RunID)
	assert.Equal(t, len(got.Findings), len(second.Findings))

	// /v1/runs lists the run.
	resp3, body3 := h.do(t, "GET", "/v1/runs", "", h.tokenPlain)
	require.Equal(t, http.StatusOK, resp3.StatusCode)
	var runs []map[string]any
	require.NoError(t, json.Unmarshal(body3, &runs))
	require.NotEmpty(t, runs)
	assert.Equal(t, "succeeded", runs[0]["status"])

	// /v1/runs/{id} fetches detail.
	resp4, body4 := h.do(t, "GET", "/v1/runs/"+got.RunID, "", h.tokenPlain)
	require.Equal(t, http.StatusOK, resp4.StatusCode)
	var detail map[string]any
	require.NoError(t, json.Unmarshal(body4, &detail))
	assert.Equal(t, "succeeded", detail["status"])
	assert.NotNil(t, detail["completed_at"])
}

func TestRuns_CannotCrossTenant(t *testing.T) {
	h := newHarness(t)
	// h's tenant runs one check.
	resp, body := h.do(t, "POST", "/v1/check", "", h.tokenPlain)
	require.Equal(t, http.StatusOK, resp.StatusCode)
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

func TestNewConcord_RequiresStore(t *testing.T) {
	_, err := server.NewConcord(server.Options{
		ControlsDir: repoControlsDir(t),
		ConfigPath:  filepath.Join(t.TempDir(), "x.yaml"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Store is required")
}
