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

func TestScheduleCreateCmd_Posts(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"s1","name":"nightly","kind":"collection.trigger","enabled":true}`))
	}))
	defer srv.Close()

	cmd := newScheduleCreateCmd()
	cmd.SetArgs([]string{
		"--name", "nightly", "--kind", "collection.trigger", "--spec", "@daily",
		"--args", `{"target":"aws"}`,
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x",
	})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/schedules" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["name"] != "nightly" || gotBody["kind"] != "collection.trigger" || gotBody["spec"] != "@daily" {
		t.Fatalf("body = %+v", gotBody)
	}
	if gotBody["enabled"] != true {
		t.Fatalf("default enabled should be true: %+v", gotBody)
	}
	args, ok := gotBody["args"].(map[string]any)
	if !ok || args["target"] != "aws" {
		t.Fatalf("args = %+v", gotBody["args"])
	}
}

func TestScheduleCreateCmd_DisabledFlag(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"s1","enabled":false}`))
	}))
	defer srv.Close()

	cmd := newScheduleCreateCmd()
	cmd.SetArgs([]string{
		"--name", "x", "--kind", "evaluation.trigger", "--spec", "@hourly", "--disabled",
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x",
	})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotBody["enabled"] != false {
		t.Fatalf("--disabled must send enabled=false: %+v", gotBody)
	}
}

func TestScheduleListCmd_Filters(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	cmd := newScheduleListCmd()
	cmd.SetArgs([]string{"--kind", "attestation.launch", "--enabled", "true",
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(gotQuery, "kind=attestation.launch") || !strings.Contains(gotQuery, "enabled=true") {
		t.Fatalf("query = %s", gotQuery)
	}
}

func TestScheduleRunCmd_PostsToRun(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	cmd := newScheduleRunCmd()
	cmd.SetArgs([]string{"s1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/schedules/s1/run" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}

func TestScheduleDisableCmd_PatchesEnabledFalse(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"s1","enabled":false}`))
	}))
	defer srv.Close()

	cmd := newScheduleEnableCmd("disable", false)
	cmd.SetArgs([]string{"s1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPatch || gotPath != "/v1/orgs/acme/schedules/s1" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["enabled"] != false {
		t.Fatalf("disable must send enabled=false: %+v", gotBody)
	}
}

func TestScheduleDeleteCmd_Deletes(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cmd := newScheduleDeleteCmd()
	cmd.SetArgs([]string{"s1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/v1/orgs/acme/schedules/s1" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}
