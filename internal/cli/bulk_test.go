package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeTempCSV(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.csv")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRiskImportCmd_UploadsCSV(t *testing.T) {
	var gotPath, gotCT, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotCT = r.URL.Path, r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		_, _ = w.Write([]byte(`{"imported":2}`))
	}))
	defer srv.Close()

	csvFile := writeTempCSV(t, "title,inherent_likelihood,inherent_impact\nA,3,3\nB,2,4\n")
	cmd := newRiskImportCmd()
	cmd.SetArgs([]string{csvFile, "--server", srv.URL, "--org-slug", "acme", "--project", "prod", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/projects/prod/risks/import" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotCT != "text/csv" {
		t.Fatalf("content-type = %s", gotCT)
	}
	if gotBody == "" || gotBody[:5] != "title" {
		t.Fatalf("body = %q", gotBody)
	}
}

func TestRiskExportCmd_WritesFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/orgs/acme/projects/prod/risks/export" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("id,title\nRISK-1,Vendor outage\n"))
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "risks.csv")
	cmd := newRiskExportCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--org-slug", "acme", "--project", "prod", "--token", "concord_x", "--out", out})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "id,title\nRISK-1,Vendor outage\n" {
		t.Fatalf("file = %q", data)
	}
}

func TestAssetImportCmd_UploadsCSV(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"created":1,"updated":0,"unchanged":1}`))
	}))
	defer srv.Close()

	csvFile := writeTempCSV(t, "type,name,external_id\napplication,x,x-1\n")
	cmd := newAssetImportCmd()
	cmd.SetArgs([]string{csvFile, "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/assets/import" {
		t.Fatalf("path = %s", gotPath)
	}
}

func TestFindingsExportCmd_PassesFilters(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte("id,control_id\n"))
	}))
	defer srv.Close()

	cmd := newFindingsExportCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--org-slug", "acme", "--project", "prod",
		"--framework", "soc2", "--status", "open", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/projects/prod/findings/export" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotQuery != "framework=soc2&status=open" {
		t.Fatalf("query = %s", gotQuery)
	}
}

func TestRiskImportCmd_SurfacesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"row 2 (\"Bad\"): invalid input"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	csvFile := writeTempCSV(t, "title,inherent_likelihood,inherent_impact\nBad,9,3\n")
	cmd := newRiskImportCmd()
	cmd.SetArgs([]string{csvFile, "--server", srv.URL, "--org-slug", "acme", "--project", "prod", "--token", "concord_x"})
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected error from 400 response")
	}
}
