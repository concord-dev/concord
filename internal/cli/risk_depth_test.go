package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRiskRollupCmd_GetsOrgRollup(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"total":3,"by_status":{"open":3},"by_severity":{"high":3},"by_category":{},"appetite_breaches":1,"kri_breaches":0,"top_residual":[]}`))
	}))
	defer srv.Close()

	cmd := newRiskRollupCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/orgs/acme/risks/rollup" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}

func TestRiskTreatmentAddCmd_PostsToProjectScopedRoute(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"t1","strategy":"mitigate","status":"planned"}`))
	}))
	defer srv.Close()

	cmd := newRiskTreatmentAddCmd()
	cmd.SetArgs([]string{"RISK-1", "--strategy", "mitigate", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/projects/default/risks/RISK-1/treatments" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["strategy"] != "mitigate" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestRiskKRIMeasureCmd_PostsMeasurement(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"value":95,"breached":true}`))
	}))
	defer srv.Close()

	cmd := newRiskKRIMeasureCmd()
	cmd.SetArgs([]string{"RISK-1", "KRI-abc", "--value", "95", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/projects/default/risks/RISK-1/kris/KRI-abc/measurements" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotBody["value"] != 95.0 {
		t.Fatalf("body value = %v", gotBody["value"])
	}
}

func TestRiskAppetiteSetCmd_CreatesWhenAbsent(t *testing.T) {
	var postPath, postMethod string
	var postBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`)) // no existing appetites → set creates
			return
		}
		postPath, postMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &postBody)
		_, _ = w.Write([]byte(`{"id":"a1","category":"security","max_score":8}`))
	}))
	defer srv.Close()

	cmd := newRiskAppetiteSetCmd()
	cmd.SetArgs([]string{"--max-score", "8", "--category", "security", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if postMethod != http.MethodPost || postPath != "/v1/orgs/acme/risk-appetites" {
		t.Fatalf("method/path = %s %s", postMethod, postPath)
	}
	if postBody["max_score"] != 8.0 || postBody["category"] != "security" {
		t.Fatalf("body = %+v", postBody)
	}
}

func TestRiskAppetiteSetCmd_UpdatesWhenPresent(t *testing.T) {
	var patchPath, patchMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[{"id":"a1","category":"security","max_score":8}]`))
			return
		}
		patchPath, patchMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"id":"a1","category":"security","max_score":6}`))
	}))
	defer srv.Close()

	cmd := newRiskAppetiteSetCmd()
	cmd.SetArgs([]string{"--max-score", "6", "--category", "security", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if patchMethod != http.MethodPatch || patchPath != "/v1/orgs/acme/risk-appetites/a1" {
		t.Fatalf("expected PATCH of the existing appetite, got %s %s", patchMethod, patchPath)
	}
}
