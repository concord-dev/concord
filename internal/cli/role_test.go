package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoleCreateCmd_PostsNameAndPerms(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"r1","name":"Compliance Lead","permissions":[{"name":"risk:read"}]}`))
	}))
	defer srv.Close()

	cmd := newRoleCreateCmd()
	cmd.SetArgs([]string{"--name", "Compliance Lead", "--perm", "risk:read", "--perm", "risk:write",
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/roles" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["name"] != "Compliance Lead" {
		t.Fatalf("body = %+v", gotBody)
	}
	perms, ok := gotBody["permissions"].([]any)
	if !ok || len(perms) != 2 || perms[0] != "risk:read" {
		t.Fatalf("permissions = %+v", gotBody["permissions"])
	}
}

func TestRoleSetPermsCmd_Patches(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"r1","permissions":[]}`))
	}))
	defer srv.Close()

	cmd := newRoleSetPermsCmd()
	cmd.SetArgs([]string{"r1", "--perm", "org:read", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPatch || gotPath != "/v1/orgs/acme/roles/r1" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if perms, ok := gotBody["permissions"].([]any); !ok || len(perms) != 1 {
		t.Fatalf("permissions = %+v", gotBody["permissions"])
	}
}

func TestRoleDeleteCmd_Deletes(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cmd := newRoleDeleteCmd()
	cmd.SetArgs([]string{"r1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/v1/orgs/acme/roles/r1" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
}

func TestRolePermissionsCmd_GetsCatalog(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`[{"name":"risk:read"}]`))
	}))
	defer srv.Close()

	cmd := newRolePermissionsCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/permissions" {
		t.Fatalf("path = %s", gotPath)
	}
}
