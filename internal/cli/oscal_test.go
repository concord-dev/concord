package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "doc.json")
	require.NoError(t, os.WriteFile(f, []byte(body), 0o644))
	return f
}

func TestRunOSCALImport_PostsCatalog(t *testing.T) {
	var gotPath, gotAuth, gotQuery string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotQuery = r.URL.Path, r.Header.Get("Authorization"), r.URL.RawQuery
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"imported":2,"controls_linked":1}`))
	}))
	defer srv.Close()

	f := writeTemp(t, `{"catalog":{"metadata":{"version":"5.1.1"}}}`)
	opts := oscalOpts{serverURL: srv.URL, operatorToken: "optok", frameworkKey: "nist-800-53"}
	require.NoError(t, runOSCALImport(context.Background(), opts, "catalog", f))

	assert.Equal(t, "/operator/v1/oscal/catalog", gotPath)
	assert.Equal(t, "Bearer optok", gotAuth)
	assert.Contains(t, gotQuery, "framework_key=nist-800-53")
	assert.Equal(t, `{"catalog":{"metadata":{"version":"5.1.1"}}}`, string(gotBody))
}

func TestRunOSCALImport_ProfilePostsBaseline(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"selected":1,"matched":1}`))
	}))
	defer srv.Close()

	f := writeTemp(t, `{"profile":{"imports":[{"include-controls":[{"with-ids":["ac-1"]}]}]}}`)
	opts := oscalOpts{serverURL: srv.URL, operatorToken: "optok", frameworkKey: "nist-800-53", baselineKey: "fedramp-moderate", version: "5.1.1"}
	require.NoError(t, runOSCALImport(context.Background(), opts, "profile", f))

	assert.Equal(t, "/operator/v1/oscal/profile", gotPath)
	assert.Contains(t, gotQuery, "baseline_key=fedramp-moderate")
	assert.Contains(t, gotQuery, "version=5.1.1")
}

func TestRunOSCALImport_Validation(t *testing.T) {
	// Missing framework-key fails before any request.
	err := runOSCALImport(context.Background(), oscalOpts{serverURL: "http://x", operatorToken: "t"}, "catalog", "/nonexistent")
	require.Error(t, err)

	// Non-2xx is surfaced.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad catalog"))
	}))
	defer srv.Close()
	f := writeTemp(t, `{}`)
	err = runOSCALImport(context.Background(), oscalOpts{serverURL: srv.URL, operatorToken: "t", frameworkKey: "x"}, "catalog", f)
	require.Error(t, err)
}
