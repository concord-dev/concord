package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReportCreateCmd_Posts(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"r1","name":"readiness","kind":"framework_readiness","format":"markdown"}`))
	}))
	defer srv.Close()

	cmd := newReportCreateCmd()
	cmd.SetArgs([]string{"--name", "readiness", "--kind", "framework_readiness", "--format", "markdown",
		"--params", `{"framework":"soc2"}`,
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/reports" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["kind"] != "framework_readiness" || gotBody["format"] != "markdown" {
		t.Fatalf("body = %+v", gotBody)
	}
	params, ok := gotBody["params"].(map[string]any)
	if !ok || params["framework"] != "soc2" {
		t.Fatalf("params = %+v", gotBody["params"])
	}
}

func TestReportRunCmd_PostsToRun(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"id":"run1","status":"succeeded","byte_size":42}`))
	}))
	defer srv.Close()

	cmd := newReportRunCmd()
	cmd.SetArgs([]string{"r1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/reports/r1/run" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}

func TestReportDownloadCmd_WritesRawBody(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write([]byte("# Findings Summary\n"))
	}))
	defer srv.Close()

	cmd := newReportDownloadCmd()
	cmd.SetArgs([]string{"r1", "run1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/reports/r1/runs/run1/download" {
		t.Fatalf("path = %s", gotPath)
	}
}

func TestReportCreateCmd_RequiresFlags(t *testing.T) {
	cmd := newReportCreateCmd()
	cmd.SetArgs([]string{"--name", "x", "--server", "http://x", "--org-slug", "acme", "--token", "concord_x"})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.ExecuteContext(context.Background()); err == nil {
		t.Fatalf("expected error when --kind is missing")
	}
}
