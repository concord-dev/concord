package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyDocCreateCmd_Posts(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"p1","title":"AUP","status":"draft"}`))
	}))
	defer srv.Close()

	cmd := newPolicyDocCreateCmd()
	cmd.SetArgs([]string{"--title", "AUP", "--category", "security", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/policy-documents" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["title"] != "AUP" || gotBody["category"] != "security" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestPolicyDocPublishCmd_PostsToPublish(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"id":"p1","title":"AUP","status":"published","version":1}`))
	}))
	defer srv.Close()

	cmd := newPolicyDocPublishCmd()
	cmd.SetArgs([]string{"p1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/policy-documents/p1/publish" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}

func TestPolicyDocApproveCmd_PostsNote(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"p1","title":"AUP","status":"approved"}`))
	}))
	defer srv.Close()

	cmd := newPolicyDocActionCmd("approve", "Approve", true)
	cmd.SetArgs([]string{"p1", "--note", "ok", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/policy-documents/p1/approve" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotBody["note"] != "ok" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestAttestationLaunchCmd_PostsPolicyID(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"c1","title":"AUP","status":"in_progress","counts":{"total":3}}`))
	}))
	defer srv.Close()

	cmd := newAttestationLaunchCmd()
	cmd.SetArgs([]string{"--policy", "p1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/attestation-campaigns" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["policy_document_id"] != "p1" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestAttestationAckCmd_PostsAgreed(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"attester_email":"o@x.com","agreed":true}`))
	}))
	defer srv.Close()

	cmd := newAttestationAckCmd()
	cmd.SetArgs([]string{"c1", "--note", "read it", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_sess_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/attestation-campaigns/c1/attest" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotBody["agreed"] != true || gotBody["note"] != "read it" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestAttestationAckCmd_RejectFlag(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"attester_email":"o@x.com","agreed":false}`))
	}))
	defer srv.Close()

	cmd := newAttestationAckCmd()
	cmd.SetArgs([]string{"c1", "--reject", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_sess_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotBody["agreed"] != false {
		t.Fatalf("--reject must send agreed=false: %+v", gotBody)
	}
}

func TestAttestationListCmd_Filters(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	cmd := newAttestationListCmd()
	cmd.SetArgs([]string{"--status", "in_progress", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(gotQuery, "status=in_progress") {
		t.Fatalf("query = %s", gotQuery)
	}
}
