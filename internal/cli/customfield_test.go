package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCustomFieldDefineCmd_Posts(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"id":"f1","entity_type":"risk","key":"tier","field_type":"select"}`))
	}))
	defer srv.Close()

	cmd := newCustomFieldDefineCmd()
	cmd.SetArgs([]string{"--entity", "risk", "--key", "tier", "--label", "Tier", "--type", "select",
		"--option", "low", "--option", "high",
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/orgs/acme/custom-fields" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["entity_type"] != "risk" || gotBody["key"] != "tier" || gotBody["field_type"] != "select" {
		t.Fatalf("body = %+v", gotBody)
	}
	opts, ok := gotBody["options"].([]any)
	if !ok || len(opts) != 2 {
		t.Fatalf("options = %+v", gotBody["options"])
	}
}

func TestCustomFieldSetCmd_ParsesTypedValues(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody struct {
		Values map[string]any `json:"values"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"values":{}}`))
	}))
	defer srv.Close()

	cmd := newCustomFieldSetCmd()
	cmd.SetArgs([]string{"risk", "r1", "--set", "impact=7", "--set", "tier=high", "--set", "active=true",
		"--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotMethod != http.MethodPut || gotPath != "/v1/orgs/acme/custom-field-values/risk/r1" {
		t.Fatalf("method/path = %s %s", gotMethod, gotPath)
	}
	// Values are typed: number 7, string "high", bool true.
	if gotBody.Values["impact"] != float64(7) {
		t.Fatalf("impact = %v (want number 7)", gotBody.Values["impact"])
	}
	if gotBody.Values["tier"] != "high" {
		t.Fatalf("tier = %v", gotBody.Values["tier"])
	}
	if gotBody.Values["active"] != true {
		t.Fatalf("active = %v (want bool true)", gotBody.Values["active"])
	}
}

func TestCustomFieldValuesCmd_Gets(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"values":{"tier":"high"}}`))
	}))
	defer srv.Close()

	cmd := newCustomFieldValuesCmd()
	cmd.SetArgs([]string{"risk", "r1", "--server", srv.URL, "--org-slug", "acme", "--token", "concord_x"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/v1/orgs/acme/custom-field-values/risk/r1" {
		t.Fatalf("path = %s", gotPath)
	}
}
