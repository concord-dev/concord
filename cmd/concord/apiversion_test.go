package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what
// was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stderr = orig
	return <-done
}

func TestApiGet_SendsVersionHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Concord-Api-Version")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	fs, err := resolveFindingsServer(srv.URL, "acme", "concord_x")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var out map[string]any
	if err := apiGet(context.Background(), fs, "/v1/orgs/acme/anything", &out); err != nil {
		t.Fatalf("apiGet: %v", err)
	}
	if got != "1" {
		t.Fatalf("Concord-Api-Version = %q, want 1", got)
	}
}

func TestApiSend_SendsVersionHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Concord-Api-Version")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	fs, err := resolveFindingsServer(srv.URL, "acme", "concord_x")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := apiSend(context.Background(), fs, http.MethodPost, "/v1/orgs/acme/x", map[string]any{"a": 1}, nil); err != nil {
		t.Fatalf("apiSend: %v", err)
	}
	if got != "1" {
		t.Fatalf("Concord-Api-Version = %q, want 1", got)
	}
}

func TestWarnIfDeprecated(t *testing.T) {
	// No Deprecation header → no output (and must not panic on nil/empty).
	quiet := captureStderr(t, func() {
		warnIfDeprecated(nil)
		warnIfDeprecated(&http.Response{Header: http.Header{}})
	})
	if quiet != "" {
		t.Fatalf("expected no warning, got %q", quiet)
	}

	// With the header → a warning naming the sunset date is printed.
	h := http.Header{}
	h.Set("Deprecation", "true")
	h.Set("Sunset", "Wed, 01 Jan 2027 00:00:00 GMT")
	out := captureStderr(t, func() { warnIfDeprecated(&http.Response{Header: h}) })
	if !strings.Contains(out, "deprecated") || !strings.Contains(out, "2027") {
		t.Fatalf("warning = %q, want it to mention deprecation + the sunset date", out)
	}
}

func TestCallAPI_SendsVersionHeaderAndWarns(t *testing.T) {
	var gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = r.Header.Get("Concord-Api-Version")
		w.Header().Set("Deprecation", "true")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var out map[string]any
	warn := captureStderr(t, func() {
		if err := callAPI(context.Background(), http.MethodGet, srv.URL+"/v1/me", "tok", nil, &out); err != nil {
			t.Fatalf("callAPI: %v", err)
		}
	})
	if gotVersion != "1" {
		t.Fatalf("Concord-Api-Version = %q, want 1", gotVersion)
	}
	if !strings.Contains(warn, "deprecated") {
		t.Fatalf("expected a deprecation warning, got %q", warn)
	}
}
