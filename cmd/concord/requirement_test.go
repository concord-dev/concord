package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequirementCoverageCmd_GetsWithFramework(t *testing.T) {
	var gotPath, gotMethod, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotQuery = r.URL.Path, r.Method, r.URL.RawQuery
		_, _ = w.Write([]byte(`[{"requirement_id":"ac-1","status":"met","control_count":1,"passing_controls":1}]`))
	}))
	defer srv.Close()

	cmd := newRequirementCoverageCmd()
	cmd.SetArgs([]string{"--framework", "soc2", "--version", "2017",
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/orgs/acme/requirements/coverage" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if !strings.Contains(gotQuery, "framework=soc2") || !strings.Contains(gotQuery, "version=2017") {
		t.Fatalf("query = %s", gotQuery)
	}
}

func TestRequirementReadinessCmd_GetsSummary(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(`{"framework":"soc2","total":3,"applicable":3,"met":1,"readiness_pct":33.3}`))
	}))
	defer srv.Close()

	cmd := newRequirementReadinessCmd()
	cmd.SetArgs([]string{"--framework", "soc2", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/requirements/readiness" {
		t.Fatalf("path = %s", gotPath)
	}
	if !strings.Contains(gotQuery, "framework=soc2") {
		t.Fatalf("query = %s", gotQuery)
	}
}

func TestRequirementShowCmd_GetsDetail(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"requirement_id":"ac-1","status":"partial","controls":[{"control_id":"C1","status":"passing"}]}`))
	}))
	defer srv.Close()

	cmd := newRequirementShowCmd()
	cmd.SetArgs([]string{"r1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/requirements/r1/readiness" {
		t.Fatalf("path = %s", gotPath)
	}
}

func TestRequirementCoverageCmd_RequiresFramework(t *testing.T) {
	cmd := newRequirementCoverageCmd()
	cmd.SetArgs([]string{"--server", "http://x", "--org-slug", "acme", "--token", "concord_x"})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.ExecuteContext(context.Background()); err == nil {
		t.Fatalf("expected error when --framework is missing")
	}
}
