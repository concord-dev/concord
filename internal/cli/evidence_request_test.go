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

func TestEvidenceRequestRequestCmd_InfersScopeAndPosts(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"e1","title":"x","status":"open"}`))
	}))
	defer srv.Close()

	cmd := newEvidenceRequestRequestCmd()
	cmd.SetArgs([]string{"--title", "Q3 cert", "--assignee", "o@x.com", "--control", "soc2.cc6.1",
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/projects/default/evidence-requests" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["scope_type"] != "control" || gotBody["control_id"] != "soc2.cc6.1" || gotBody["assignee_email"] != "o@x.com" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestEvidenceRequestSubmitCmd_PostsToSubmit(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"id":"e1","title":"x","status":"submitted"}`))
	}))
	defer srv.Close()

	cmd := newEvidenceRequestSubmitCmd()
	cmd.SetArgs([]string{"e1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/projects/default/evidence-requests/e1/submit" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}

func TestEvidenceRequestAcceptCmd_PostsNote(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"e1","title":"x","status":"accepted"}`))
	}))
	defer srv.Close()

	cmd := newEvidenceRequestAcceptCmd()
	cmd.SetArgs([]string{"e1", "--note", "ok", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/projects/default/evidence-requests/e1/accept" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotBody["note"] != "ok" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestEvidenceRequestAttachCmd_PostsAttachmentID(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cmd := newEvidenceRequestAttachCmd()
	cmd.SetArgs([]string{"e1", "att-123", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/projects/default/evidence-requests/e1/attachments" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["attachment_id"] != "att-123" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestEvidenceRequestListCmd_Filters(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	cmd := newEvidenceRequestListCmd()
	cmd.SetArgs([]string{"--status", "open", "--assignee", "o@x.com", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(gotQuery, "status=open") || !strings.Contains(gotQuery, "assignee=o%40x.com") {
		t.Fatalf("query = %s", gotQuery)
	}
}

func TestEvidenceRequestCampaignCmd_PostsToCampaign(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"id":"wf1"}`))
	}))
	defer srv.Close()

	cmd := newEvidenceRequestCampaignCmd()
	cmd.SetArgs([]string{"e1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/projects/default/evidence-requests/e1/campaign" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}
