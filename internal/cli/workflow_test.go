package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestListWorkflows_BuildsQueryAndParses(t *testing.T) {
	var gotPath, gotQuery, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotAuth = r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[{"id":"11111111-1111-1111-1111-111111111111","kind":"access_review_campaign","status":"running","current_state":"monitoring"}]`))
	}))
	defer srv.Close()

	fs := findingsServer{url: srv.URL, orgSlug: "acme", token: "concord_x"}
	rows, err := listWorkflows(context.Background(), fs, "access_review_campaign", "running", 50)
	if err != nil {
		t.Fatalf("listWorkflows: %v", err)
	}
	if gotPath != "/v1/orgs/acme/workflows" {
		t.Fatalf("path = %q", gotPath)
	}
	q, _ := url.ParseQuery(gotQuery)
	if q.Get("kind") != "access_review_campaign" || q.Get("status") != "running" || q.Get("limit") != "50" {
		t.Fatalf("query = %q", gotQuery)
	}
	if gotAuth != "Bearer concord_x" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if len(rows) != 1 || rows[0].Kind != "access_review_campaign" || rows[0].Status != "running" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestListWorkflows_OmitsEmptyFilters(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	fs := findingsServer{url: srv.URL, orgSlug: "acme", token: "concord_x"}
	if _, err := listWorkflows(context.Background(), fs, "", "", 0); err != nil {
		t.Fatalf("listWorkflows: %v", err)
	}
	if gotQuery != "" {
		t.Fatalf("expected no query string, got %q", gotQuery)
	}
}

func TestGetWorkflowDetail_ParsesInstanceStepsTimers(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{
			"instance":{"id":"abc","kind":"remediation_campaign","status":"waiting","current_state":"tracking"},
			"steps":[{"id":"s1","step_key":"notify-1","action":"notify","status":"succeeded","attempt_count":1,"max_attempts":5}],
			"timers":[{"id":"t1","timer_key":"breach","signal":"breached","fire_at":"2026-07-01T00:00:00Z"}]
		}`))
	}))
	defer srv.Close()

	fs := findingsServer{url: srv.URL, orgSlug: "acme", token: "concord_x"}
	d, err := getWorkflowDetail(context.Background(), fs, "abc")
	if err != nil {
		t.Fatalf("getWorkflowDetail: %v", err)
	}
	if gotPath != "/v1/orgs/acme/workflows/abc" {
		t.Fatalf("path = %q", gotPath)
	}
	if d.Instance.Kind != "remediation_campaign" || d.Instance.CurrentState != "tracking" {
		t.Fatalf("instance = %+v", d.Instance)
	}
	if len(d.Steps) != 1 || d.Steps[0].Action != "notify" {
		t.Fatalf("steps = %+v", d.Steps)
	}
	if len(d.Timers) != 1 || d.Timers[0].Signal != "breached" {
		t.Fatalf("timers = %+v", d.Timers)
	}
}

func TestCancelWorkflow_PostsReason(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"abc","status":"cancelled"}`))
	}))
	defer srv.Close()

	fs := findingsServer{url: srv.URL, orgSlug: "acme", token: "concord_x"}
	inst, err := cancelWorkflow(context.Background(), fs, "abc", "duplicate campaign")
	if err != nil {
		t.Fatalf("cancelWorkflow: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/workflows/abc/cancel" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["reason"] != "duplicate campaign" {
		t.Fatalf("body reason = %v", gotBody["reason"])
	}
	if inst.Status != "cancelled" {
		t.Fatalf("status = %q", inst.Status)
	}
}

func TestCancelWorkflow_NoReasonSendsNoBody(t *testing.T) {
	var gotLen int64
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLen, gotCT = r.ContentLength, r.Header.Get("Content-Type")
		_, _ = w.Write([]byte(`{"id":"abc","status":"cancelled"}`))
	}))
	defer srv.Close()

	fs := findingsServer{url: srv.URL, orgSlug: "acme", token: "concord_x"}
	if _, err := cancelWorkflow(context.Background(), fs, "abc", "  "); err != nil {
		t.Fatalf("cancelWorkflow: %v", err)
	}
	if gotLen != 0 {
		t.Fatalf("expected empty body, got content-length %d", gotLen)
	}
	if gotCT != "" {
		t.Fatalf("expected no content-type for empty body, got %q", gotCT)
	}
}

func TestListWorkflows_SurfacesNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	fs := findingsServer{url: srv.URL, orgSlug: "acme", token: "concord_x"}
	if _, err := listWorkflows(context.Background(), fs, "", "", 0); err == nil {
		t.Fatal("expected an error on 403")
	}
}

func TestAccessReviewCampaign_PostsToCycleCampaign(t *testing.T) {
	var gotPath, gotMethod, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotAuth = r.URL.Path, r.Method, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"wf1","kind":"access_review_campaign","status":"running"}`))
	}))
	defer srv.Close()

	cmd := newAccessReviewCampaignCmd()
	cmd.SetArgs([]string{"cyc-1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/access-reviews/cyc-1/campaign" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotAuth != "Bearer concord_x" {
		t.Fatalf("auth = %q", gotAuth)
	}
}

func TestFindingsCampaign_PostsToProjectScopedRoute(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"wf2","kind":"remediation_campaign","status":"running"}`))
	}))
	defer srv.Close()

	cmd := newFindingsCampaignCmd()
	cmd.SetArgs([]string{"FIND-abc", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x", "--project", "prod"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/projects/prod/findings/FIND-abc/remediation/campaign" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}

func TestGetWorkflowGraph_ReturnsDOT(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"kind":"access_review_campaign","dot":"digraph {\n  monitoring;\n}"}`))
	}))
	defer srv.Close()

	fs := findingsServer{url: srv.URL, orgSlug: "acme", token: "concord_x"}
	dot, err := getWorkflowGraph(context.Background(), fs, "access_review_campaign")
	if err != nil {
		t.Fatalf("getWorkflowGraph: %v", err)
	}
	if gotPath != "/v1/orgs/acme/workflow-definitions/access_review_campaign/graph" {
		t.Fatalf("path = %q", gotPath)
	}
	if !strings.Contains(dot, "digraph") || !strings.Contains(dot, "monitoring") {
		t.Fatalf("dot = %q", dot)
	}
}

func TestTruncate_RuneSafe(t *testing.T) {
	for _, c := range []struct {
		name string
		in   string
		n    int
	}{
		{"empty", "", 48},
		{"ascii-short", "short error", 48},
		{"multibyte-long", strings.Repeat("é", 60), 48},
		{"emoji-long", strings.Repeat("🔥", 30), 48},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := truncate(c.in, c.n)
			if !utf8.ValidString(got) {
				t.Fatalf("truncate(%q) produced invalid UTF-8: %q", c.in, got)
			}
			if c.in == "" && got != "—" {
				t.Fatalf("empty input should render as dash, got %q", got)
			}
		})
	}
}
