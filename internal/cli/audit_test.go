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

func TestEngagementCreateCmd_Posts(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"e1","name":"SOC 2 2026","status":"planned"}`))
	}))
	defer srv.Close()

	cmd := newEngagementCreateCmd()
	cmd.SetArgs([]string{"--name", "SOC 2 2026", "--framework", "soc2",
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/engagements" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["name"] != "SOC 2 2026" || gotBody["framework"] != "soc2" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestEngagementStartCmd_PostsToStart(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"id":"e1","status":"in_fieldwork"}`))
	}))
	defer srv.Close()

	cmd := newEngagementActionCmd("start")
	cmd.SetArgs([]string{"e1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/engagements/e1/start" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}

func TestEngagementListCmd_Filters(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	cmd := newEngagementListCmd()
	cmd.SetArgs([]string{"--status", "in_fieldwork", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(gotQuery, "status=in_fieldwork") {
		t.Fatalf("query = %s", gotQuery)
	}
}

func TestPBCCreateCmd_PostsEngagementAndTitle(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"p1","title":"access listing","status":"open"}`))
	}))
	defer srv.Close()

	cmd := newPBCCreateCmd()
	cmd.SetArgs([]string{"--engagement", "e1", "--title", "access listing", "--assignee", "it@acme.com",
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/pbc-requests" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotBody["engagement_id"] != "e1" || gotBody["title"] != "access listing" || gotBody["assignee_email"] != "it@acme.com" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestPBCAcceptCmd_PostsNote(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"p1","status":"accepted"}`))
	}))
	defer srv.Close()

	cmd := newPBCActionCmd("accept")
	cmd.SetArgs([]string{"p1", "--note", "ok", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/pbc-requests/p1/accept" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotBody["note"] != "ok" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestPBCCreateCmd_RequiresFlags(t *testing.T) {
	cmd := newPBCCreateCmd()
	cmd.SetArgs([]string{"--title", "x", "--server", "http://x", "--org-slug", "acme", "--token", "concord_x"})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.ExecuteContext(context.Background()); err == nil {
		t.Fatalf("expected error when --engagement and --assignee are missing")
	}
}
