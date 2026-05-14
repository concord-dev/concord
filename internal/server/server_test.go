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
		t.Skipf("skipping: Postgres not reachable at %s: %v", dsn, err)
	}
	require.NoError(t, s.Migrate(ctx))
	t.Cleanup(s.Close)
	return s
}

// harness bundles a running httptest server with a pre-built tenant: one
// org, one API token, one user (with a known password and the owner role).
type harness struct {
	srv        *httptest.Server
	c          *server.Concord
	st         *store.Store
	org        store.Organization
	user       store.User
	password   string
	apiToken   string // plaintext concord_... token
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

	ctx := context.Background()
	org, err := st.CreateOrganization(ctx, "Test Org", "test-"+uuid.NewString()[:8])
	require.NoError(t, err)
	password := "hunter2-" + uuid.NewString()[:8]
	user, err := st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "Test", LastName: "User",
		Email: fmt.Sprintf("u-%s@example.com", uuid.NewString()[:8]),
		Password: password,
	})
	require.NoError(t, err)
	owner, err := st.GetRoleByName(ctx, "owner")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, user.ID, org.ID, owner.ID))
	_, plain, err := st.CreateAPIToken(ctx, org.ID, "ci", &user.ID)
	require.NoError(t, err)

	return &harness{srv: ts, c: c, st: st, org: org, user: user,
		password: password, apiToken: plain}
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

// ─── Public ────────────────────────────────────────────────────────────

func TestHealth_NoAuth(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/healthz", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"status":"ok"}`, string(body))
}

// ─── Auth: login flow ──────────────────────────────────────────────────

func TestLogin_HappyPath_ReturnsSessionToken(t *testing.T) {
	h := newHarness(t)
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	var got struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
		User      store.User `json:"user"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.True(t, strings.HasPrefix(got.Token, "concord_sess_"))
	assert.True(t, got.ExpiresAt.After(time.Now()))
	assert.Equal(t, h.user.Email, got.User.Email)
}

func TestLogin_BadPasswordReturnsGenericMessage(t *testing.T) {
	h := newHarness(t)
	body := fmt.Sprintf(`{"email":%q,"password":"wrong"}`, h.user.Email)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(raw), "invalid credentials")
	assert.NotContains(t, string(raw), h.user.Email,
		"error must not echo the email back (prevents enumeration)")
}

func TestLogin_UnknownEmailReturnsSameGenericMessage(t *testing.T) {
	h := newHarness(t)
	resp, raw := h.do(t, "POST", "/v1/auth/login",
		`{"email":"nobody@example.com","password":"x"}`, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(raw), "invalid credentials")
}

func TestLogout_RevokesSession(t *testing.T) {
	h := newHarness(t)
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	_, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	var got struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))

	respL, _ := h.do(t, "POST", "/v1/auth/logout", "", got.Token)
	assert.Equal(t, http.StatusNoContent, respL.StatusCode)

	// Token must now be rejected.
	respMe, _ := h.do(t, "GET", "/v1/me", "", got.Token)
	assert.Equal(t, http.StatusUnauthorized, respMe.StatusCode)
}

// ─── Session-scoped endpoints ─────────────────────────────────────────

func TestSessionMe_ReturnsUser(t *testing.T) {
	h := newHarness(t)
	sessTok := h.login(t)
	resp, raw := h.do(t, "GET", "/v1/me", "", sessTok)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var u store.User
	require.NoError(t, json.Unmarshal(raw, &u))
	assert.Equal(t, h.user.ID, u.ID)
}

func TestSessionOrgs_ListsUserMemberships(t *testing.T) {
	h := newHarness(t)
	sessTok := h.login(t)
	resp, raw := h.do(t, "GET", "/v1/me/orgs", "", sessTok)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var orgs []store.UserOrg
	require.NoError(t, json.Unmarshal(raw, &orgs))
	require.Len(t, orgs, 1)
	assert.Equal(t, h.org.Slug, orgs[0].Organization.Slug)
	assert.Equal(t, "owner", orgs[0].Roles[0].Name)
}

func TestSessionRoute_RejectsAPIToken(t *testing.T) {
	h := newHarness(t)
	// API tokens must NOT satisfy session-only routes.
	resp, body := h.do(t, "GET", "/v1/me", "", h.apiToken)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(body), "session token")
}

// ─── Org-scoped: API token path ───────────────────────────────────────

func TestOrgAPI_WithAPIToken_PermitsRead(t *testing.T) {
	h := newHarness(t)
	resp, raw := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/frameworks", "", h.apiToken)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
}

func TestOrgAPI_TokenAgainstWrongOrgIsForbidden(t *testing.T) {
	h := newHarness(t)
	other, _ := h.st.CreateOrganization(context.Background(), "Other", uniqueSlug("other"))
	resp, body := h.do(t, "GET", "/v1/orgs/"+other.Slug+"/frameworks", "", h.apiToken)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "not scoped")
}

func TestOrgAPI_UnknownOrgReturns404(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, "GET", "/v1/orgs/nope-"+uuid.NewString()[:8]+"/frameworks", "", h.apiToken)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ─── Org-scoped: session path with RBAC ───────────────────────────────

func TestOrgAPI_OwnerSessionCanCreateRun(t *testing.T) {
	h := newHarness(t)
	sessTok := h.login(t)
	resp, _ := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", sessTok)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode,
		"owner has runs:create — session-driven /check must succeed")
}

func TestOrgAPI_ViewerSessionForbiddenFromCreateRun(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Spin up a viewer user attached to the harness org.
	viewerEmail := uniqueEmail("viewer")
	viewerPass := "viewer-pass"
	viewer, _ := h.st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "View", LastName: "Er", Email: viewerEmail, Password: viewerPass,
	})
	viewerRole, _ := h.st.GetRoleByName(ctx, "viewer")
	require.NoError(t, h.st.AssignRole(ctx, viewer.ID, h.org.ID, viewerRole.ID))

	// Log the viewer in.
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, viewerEmail, viewerPass)
	_, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	var got struct{ Token string `json:"token"` }
	require.NoError(t, json.Unmarshal(raw, &got))

	// Viewer can READ.
	respR, _ := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/frameworks", "", got.Token)
	assert.Equal(t, http.StatusOK, respR.StatusCode, "viewer holds controls:read")

	// Viewer cannot CREATE runs.
	respC, bodyC := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", got.Token)
	assert.Equal(t, http.StatusForbidden, respC.StatusCode)
	assert.Contains(t, string(bodyC), "runs:create")
}

func TestOrgMe_ReportsPermissionsForSessionUser(t *testing.T) {
	h := newHarness(t)
	sessTok := h.login(t)
	resp, raw := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/me", "", sessTok)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got struct {
		Permissions []string `json:"permissions"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Contains(t, got.Permissions, "runs:create", "owner should hold runs:create")
	assert.Contains(t, got.Permissions, "org:delete", "owner should hold org:delete")
}

// ─── Admin (CONCORD_ADMIN_TOKEN) ──────────────────────────────────────

func TestAdmin_RequiresAdminToken(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/admin/v1/orgs", "", h.apiToken)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(body), "invalid admin token")
}

func TestAdmin_CreateUserAndAssignRoles(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("invitee")
	body := fmt.Sprintf(`{"first_name":"Invite","last_name":"Pending","email":%q,"password":"pass-1234"}`, email)
	resp, raw := h.do(t, "POST", "/admin/v1/users", body, testAdminToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	// Assign two roles in one call.
	addBody := fmt.Sprintf(`{"email":%q,"roles":["admin","viewer"]}`, email)
	resp2, raw2 := h.do(t, "POST", "/admin/v1/orgs/"+h.org.Slug+"/members",
		addBody, testAdminToken)
	require.Equal(t, http.StatusCreated, resp2.StatusCode, string(raw2))

	// Verify via list members.
	respL, rawL := h.do(t, "GET", "/admin/v1/orgs/"+h.org.Slug+"/members",
		"", testAdminToken)
	require.Equal(t, http.StatusOK, respL.StatusCode)
	var members []store.OrgMember
	require.NoError(t, json.Unmarshal(rawL, &members))
	// Harness preloaded an "owner" user; the new invitee is the second.
	var found *store.OrgMember
	for i := range members {
		if members[i].User.Email == email {
			found = &members[i]
		}
	}
	require.NotNil(t, found, "newly-invited user must appear in members list")
	assert.Len(t, found.Roles, 2)
}

func TestAdmin_AddMember_UnknownRoleRejected(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("badrole")
	body := fmt.Sprintf(`{"first_name":"X","last_name":"Y","email":%q}`, email)
	resp, _ := h.do(t, "POST", "/admin/v1/users", body, testAdminToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	addBody := fmt.Sprintf(`{"email":%q,"roles":["superuser"]}`, email)
	resp2, raw := h.do(t, "POST", "/admin/v1/orgs/"+h.org.Slug+"/members",
		addBody, testAdminToken)
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	assert.Contains(t, string(raw), "unknown role superuser")
}

func TestAdmin_RevokeToken_BlocksFutureUse(t *testing.T) {
	h := newHarness(t)
	// Mint a fresh token via the admin API.
	respC, rawC := h.do(t, "POST", "/admin/v1/orgs/"+h.org.Slug+"/tokens",
		`{"name":"ephemeral"}`, testAdminToken)
	require.Equal(t, http.StatusCreated, respC.StatusCode)
	var tok struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rawC, &tok))

	respD, _ := h.do(t, "DELETE", "/admin/v1/orgs/"+h.org.Slug+"/tokens/"+tok.ID,
		"", testAdminToken)
	assert.Equal(t, http.StatusNoContent, respD.StatusCode)

	resp, _ := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/frameworks", "", tok.Token)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAdmin_ListRoles_ShowsPermissionBundles(t *testing.T) {
	h := newHarness(t)
	resp, raw := h.do(t, "GET", "/admin/v1/roles", "", testAdminToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var roles []struct {
		Name        string             `json:"name"`
		Permissions []store.Permission `json:"permissions"`
	}
	require.NoError(t, json.Unmarshal(raw, &roles))
	require.Len(t, roles, 4)
	for _, r := range roles {
		if r.Name == "owner" {
			assert.GreaterOrEqual(t, len(r.Permissions), 16,
				"owner should be bound to every seeded permission")
		}
		if r.Name == "viewer" {
			assert.LessOrEqual(t, len(r.Permissions), 6, "viewer is read-only")
		}
	}
}

// ─── Async runs ───────────────────────────────────────────────────────

func TestCheck_ReturnsAcceptedAndPollSucceeds(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", h.apiToken)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, string(body))
	var enq struct {
		RunID   string `json:"run_id"`
		PollURL string `json:"poll_url"`
	}
	require.NoError(t, json.Unmarshal(body, &enq))
	assert.Contains(t, enq.PollURL, "/v1/orgs/"+h.org.Slug+"/runs/")

	var detail map[string]any
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp2, body2 := h.do(t, "GET", enq.PollURL, "", h.apiToken)
		require.Equal(t, http.StatusOK, resp2.StatusCode)
		require.NoError(t, json.Unmarshal(body2, &detail))
		if detail["status"] != "pending" && detail["status"] != "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Equal(t, "succeeded", detail["status"])

	// /findings lists the same run.
	respF, bodyF := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/findings", "", h.apiToken)
	require.Equal(t, http.StatusOK, respF.StatusCode)
	var findings struct {
		Findings []apiv1.Finding `json:"findings"`
		RunID    string          `json:"run_id"`
	}
	require.NoError(t, json.Unmarshal(bodyF, &findings))
	assert.Equal(t, enq.RunID, findings.RunID)
	assert.Equal(t, len(h.c.Controls), len(findings.Findings))
}

// ─── SSE ──────────────────────────────────────────────────────────────

func TestEvents_StreamsLifecycle(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET", h.srv.URL+"/v1/orgs/"+h.org.Slug+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+h.apiToken)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Eventually(t, func() bool {
		return h.c.Bus().SubscriberCount(h.org.ID) > 0
	}, 2*time.Second, 10*time.Millisecond)

	respCheck, _ := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", h.apiToken)
	require.Equal(t, http.StatusAccepted, respCheck.StatusCode)

	frames := make(chan sseFrame, 32)
	go func() { defer close(frames); readSSEFrames(resp.Body, frames) }()

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
			}
		case <-deadline:
			t.Fatalf("timed out; started=%v completed=%v", sawStarted, sawCompleted)
		}
	}
	assert.True(t, sawStarted)
}

// ─── Per-org control overrides ────────────────────────────────────────

func TestOverrides_PutGetListDelete(t *testing.T) {
	h := newHarness(t)
	base := "/v1/orgs/" + h.org.Slug + "/controls/SOC2-CC8.1/overrides"

	// No override yet → 404.
	respMiss, _ := h.do(t, "GET", base, "", h.apiToken)
	assert.Equal(t, http.StatusNotFound, respMiss.StatusCode)

	// PUT a value.
	respPut, raw := h.do(t, "PUT", base, `{"params":{"min_reviewers":4}}`, h.apiToken)
	require.Equal(t, http.StatusOK, respPut.StatusCode, string(raw))
	var env struct {
		ControlID string                 `json:"control_id"`
		Params    map[string]any         `json:"params"`
	}
	require.NoError(t, json.Unmarshal(raw, &env))
	assert.Equal(t, "SOC2-CC8.1", env.ControlID)
	assert.EqualValues(t, 4, env.Params["min_reviewers"])

	// GET returns the same envelope.
	respGet, rawGet := h.do(t, "GET", base, "", h.apiToken)
	require.Equal(t, http.StatusOK, respGet.StatusCode)
	require.NoError(t, json.Unmarshal(rawGet, &env))
	assert.EqualValues(t, 4, env.Params["min_reviewers"])

	// LIST contains exactly the one row.
	respList, rawList := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/overrides", "", h.apiToken)
	require.Equal(t, http.StatusOK, respList.StatusCode)
	var list []struct {
		ControlID string `json:"control_id"`
	}
	require.NoError(t, json.Unmarshal(rawList, &list))
	require.Len(t, list, 1)
	assert.Equal(t, "SOC2-CC8.1", list[0].ControlID)

	// DELETE removes it.
	respDel, _ := h.do(t, "DELETE", base, "", h.apiToken)
	assert.Equal(t, http.StatusNoContent, respDel.StatusCode)
	respGet2, _ := h.do(t, "GET", base, "", h.apiToken)
	assert.Equal(t, http.StatusNotFound, respGet2.StatusCode)
}

func TestOverrides_UnknownControlReturns404(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "PUT",
		"/v1/orgs/"+h.org.Slug+"/controls/MADE-UP/overrides",
		`{"params":{"x":1}}`, h.apiToken)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, string(body), "no control with id")
	assert.Contains(t, string(body), "MADE-UP")
}

func TestOverrides_MissingParamsBodyReturns400(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "PUT",
		"/v1/orgs/"+h.org.Slug+"/controls/SOC2-CC8.1/overrides",
		`{"not_params":1}`, h.apiToken)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "`params` is required")
}

func TestOverrides_RequireOverridePermission(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Spin up a viewer (read-only) and login.
	email := uniqueEmail("viewer-ovr")
	pw := "v"
	v, _ := h.st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "V", LastName: "V", Email: email, Password: pw,
	})
	viewer, _ := h.st.GetRoleByName(ctx, "viewer")
	require.NoError(t, h.st.AssignRole(ctx, v.ID, h.org.ID, viewer.ID))
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, pw)
	_, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	var got struct{ Token string `json:"token"` }
	require.NoError(t, json.Unmarshal(raw, &got))

	// Viewer can GET (controls:read).
	respR, _ := h.do(t, "GET",
		"/v1/orgs/"+h.org.Slug+"/overrides", "", got.Token)
	assert.Equal(t, http.StatusOK, respR.StatusCode)

	// Viewer cannot PUT (controls:override).
	respW, bodyW := h.do(t, "PUT",
		"/v1/orgs/"+h.org.Slug+"/controls/SOC2-CC8.1/overrides",
		`{"params":{"min_reviewers":99}}`, got.Token)
	assert.Equal(t, http.StatusForbidden, respW.StatusCode)
	assert.Contains(t, string(bodyW), "controls:override")
}

// TestOverrides_TightenedThresholdFlipsRunToFail is the integration test that
// proves the override actually reaches the runner. The harness fixture for
// SOC2-CC8.1 has required_approving_review_count == 2; an override of
// min_reviewers=3 should turn the pass into a fail.
func TestOverrides_TightenedThresholdFlipsRunToFail(t *testing.T) {
	h := newHarness(t)

	// Baseline: a run with no overrides → CC8.1 passes.
	resp1, body1 := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", h.apiToken)
	require.Equal(t, http.StatusAccepted, resp1.StatusCode)
	var enq1 struct{ PollURL string `json:"poll_url"` }
	require.NoError(t, json.Unmarshal(body1, &enq1))
	baseline := pollRunFindings(t, h, enq1.PollURL)
	assert.Equal(t, "pass", findingStatus(baseline, "SOC2-CC8.1"))

	// Install a stricter override.
	respPut, _ := h.do(t, "PUT",
		"/v1/orgs/"+h.org.Slug+"/controls/SOC2-CC8.1/overrides",
		`{"params":{"min_reviewers":3}}`, h.apiToken)
	require.Equal(t, http.StatusOK, respPut.StatusCode)

	// New run → CC8.1 now fails because the fixture only carries 2 reviewers.
	resp2, body2 := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", h.apiToken)
	require.Equal(t, http.StatusAccepted, resp2.StatusCode)
	var enq2 struct{ PollURL string `json:"poll_url"` }
	require.NoError(t, json.Unmarshal(body2, &enq2))
	tightened := pollRunFindings(t, h, enq2.PollURL)
	assert.Equal(t, "fail", findingStatus(tightened, "SOC2-CC8.1"),
		"override of min_reviewers=3 should turn the run from pass to fail")
}

// pollRunFindings spins on GET /runs/{id} until the run reaches a terminal
// state, then returns the findings array.
func pollRunFindings(t *testing.T, h *harness, pollURL string) []apiv1.Finding {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, body := h.do(t, "GET", pollURL, "", h.apiToken)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var detail struct {
			Status   string          `json:"status"`
			Findings []apiv1.Finding `json:"findings"`
		}
		require.NoError(t, json.Unmarshal(body, &detail))
		if detail.Status == "succeeded" || detail.Status == "failed" {
			return detail.Findings
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("run %q never completed within 15s", pollURL)
	return nil
}

func findingStatus(findings []apiv1.Finding, controlID string) string {
	for _, f := range findings {
		if f.ControlID == controlID {
			return string(f.Status)
		}
	}
	return ""
}

// ─── Worker / queue ──────────────────────────────────────────────────

func TestCheck_QueueFullReturns503(t *testing.T) {
	st := openStore(t)
	c, err := server.NewConcord(server.Options{
		ControlsDir: repoControlsDir(t), ConfigPath: filepath.Join(t.TempDir(), "x.yaml"),
		FixturesOnly: true, Store: st, AdminToken: testAdminToken, Version: "test",
		Worker: server.WorkerOpts{PoolSize: 1, QueueSize: 1},
	})
	require.NoError(t, err)
	ts := httptest.NewServer(c.Router())
	t.Cleanup(ts.Close)

	ctx := context.Background()
	org, _ := st.CreateOrganization(ctx, "QFull", uniqueSlug("qfull"))
	_, tok, _ := st.CreateAPIToken(ctx, org.ID, "ci", nil)

	statuses := make(chan int, 5)
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", ts.URL+"/v1/orgs/"+org.Slug+"/check", nil)
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
	sawQF := false
	for s := range statuses {
		if s == http.StatusServiceUnavailable {
			sawQF = true
		}
	}
	assert.True(t, sawQF, "queue=1 + pool=1 with 5 concurrent requests must surface 503")
}

// ─── Misc ────────────────────────────────────────────────────────────

func TestBearer_CaseInsensitive(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET",
		h.srv.URL+"/v1/orgs/"+h.org.Slug+"/frameworks", bytes.NewReader(nil))
	req.Header.Set("Authorization", "bearer "+h.apiToken)
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

// ─── Helpers ────────────────────────────────────────────────────────

// login posts to /v1/auth/login with the harness credentials and returns
// the freshly-minted session token plaintext.
func (h *harness) login(t *testing.T) string {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))
	var got struct{ Token string `json:"token"` }
	require.NoError(t, json.Unmarshal(raw, &got))
	return got.Token
}

func uniqueSlug(p string) string  { return fmt.Sprintf("%s-%s", p, uuid.NewString()[:8]) }
func uniqueEmail(p string) string { return fmt.Sprintf("%s+%s@example.com", p, uuid.NewString()[:8]) }

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
