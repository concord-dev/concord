package server_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

func parseJSON(b []byte, v any) error { return json.Unmarshal(b, v) }

func TestAuditPackage_OwnerDownloadsBundleThroughHTTP(t *testing.T) {
	h := newHarness(t)
	submitBody := `{
		"agent":{"version":"smoke"},
		"started_at":"2026-06-04T11:00:00Z","completed_at":"2026-06-04T11:00:01Z",
		"summary":{"pass":1},
		"findings":[{"control_id":"a","status":"pass"}]
	}`
	resp, _ := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", submitBody, h.apiToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	sess := h.login(t)
	resp, raw := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/audit-package", "", sess)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "status: %s", raw)
	assert.Equal(t, "application/zip", resp.Header.Get("Content-Type"))
	disp := resp.Header.Get("Content-Disposition")
	assert.True(t, strings.HasPrefix(disp, `attachment; filename="audit-package-`+h.org.Slug+`-`),
		"Content-Disposition must hint a meaningful filename so curl/browsers save it well; got %q", disp)

	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	require.NoError(t, err)
	have := map[string]bool{}
	for _, f := range zr.File {
		have[f.Name] = true
	}
	for _, want := range []string{
		"metadata.json", "findings/latest.json", "runs.csv",
		"audit-events.csv", "drift-events.csv", "controls-overrides.json",
	} {
		assert.Truef(t, have[want], "ZIP must contain %s — that's the wire contract auditors expect", want)
	}
}

func TestAuditPackage_ExportEmitsAuditEventForTraceability(t *testing.T) {
	h := newHarness(t)
	sess := h.login(t)
	resp, _ := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/audit-package", "", sess)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	rows, err := h.st.Pool().Query(context.Background(),
		`SELECT action, target_id, details FROM audit_event
		 WHERE action LIKE 'audit_package.%' AND org_id = $1`,
		h.org.ID)
	require.NoError(t, err)
	defer rows.Close()
	var hit bool
	for rows.Next() {
		hit = true
	}
	assert.True(t, hit, "audit_package.export must persist for every download — bundles are themselves auditable")
}

func TestAuditPackage_MemberWithoutAuditReadIs403(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	password := "viewer-pw-" + h.org.Slug
	viewer, err := h.st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "V", LastName: "wr",
		Email:    "viewer-audit-" + h.org.Slug + "@example.com",
		Password: password,
	})
	require.NoError(t, err)
	role, err := h.st.GetRoleByName(ctx, "viewer")
	require.NoError(t, err)
	require.NoError(t, h.st.AssignRole(ctx, viewer.ID, h.org.ID, role.ID))

	body := fmt.Sprintf(`{"email":%q,"password":%q}`, viewer.Email, password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "login: %s", raw)
	var loginRes struct {
		Token string `json:"token"`
	}
	require.NoError(t, parseJSON(raw, &loginRes))

	resp, _ = h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/audit-package", "", loginRes.Token)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"viewer role must NOT be able to export audit packages — the bundle contains the full audit trail")
}

func TestAuditPackage_RejectsMalformedQueryParams(t *testing.T) {
	h := newHarness(t)
	sess := h.login(t)
	cases := []struct {
		name, q string
		want    int
	}{
		{"bad since", "?since=not-a-date", http.StatusBadRequest},
		{"bad max_runs", "?max_runs=zero", http.StatusBadRequest},
		{"negative cap", "?max_audit_events=-1", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := h.do(t, "GET",
				"/v1/orgs/"+h.org.Slug+"/audit-package"+tc.q, "", sess)
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}
}
