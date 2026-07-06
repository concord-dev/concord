package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExceptionRequestCmd_InfersScopeAndPosts(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"e1","title":"x","state":"pending"}`))
	}))
	defer srv.Close()

	cmd := newExceptionRequestCmd()
	cmd.SetArgs([]string{"--title", "Accept gap", "--control", "aws.s3.logging",
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/projects/default/exceptions" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["scope_type"] != "control" || gotBody["control_id"] != "aws.s3.logging" {
		t.Fatalf("scope not inferred from --control: %+v", gotBody)
	}
}

func TestExceptionApproveCmd_PostsToApproveRoute(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"id":"e1","title":"x","state":"active"}`))
	}))
	defer srv.Close()

	cmd := newExceptionApproveCmd()
	cmd.SetArgs([]string{"e1", "--note", "ok", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/projects/default/exceptions/e1/approve" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}

func TestExceptionRenewCmd_RequiresAndSendsExpiry(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"e1","title":"x","state":"active"}`))
	}))
	defer srv.Close()

	cmd := newExceptionRenewCmd()
	cmd.SetArgs([]string{"e1", "--expires", "90d", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/projects/default/exceptions/e1/renew" {
		t.Fatalf("path = %s", gotPath)
	}
	if _, ok := gotBody["expires_at"]; !ok {
		t.Fatalf("renew must send expires_at: %+v", gotBody)
	}
}

func TestExceptionListCmd_ActiveFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	cmd := newExceptionListCmd()
	cmd.SetArgs([]string{"--active", "--status", "approved", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(gotQuery, "active=true") || !strings.Contains(gotQuery, "status=approved") {
		t.Fatalf("query = %s", gotQuery)
	}
}

func TestExceptionRollupCmd_GetsOrgRollup(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"total":1,"active":1,"expiring_soon":0,"by_state":{"active":1},"by_scope":{"control":1}}`))
	}))
	defer srv.Close()

	cmd := newExceptionRollupCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/orgs/acme/exceptions/rollup" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}
