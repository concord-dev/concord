package auditpackage_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/auditpackage"
	"github.com/concord-dev/concord/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://concord:concord-dev@127.0.0.1:5432/concord?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := store.Open(ctx, dsn, store.PoolOptions{MaxConns: 4, MinConns: 1})
	if err != nil {
		t.Skipf("skipping: Postgres not reachable at %s: %v", dsn, err)
	}
	require.NoError(t, s.Migrate(ctx))
	t.Cleanup(s.Close)
	return s
}

func slug(p string) string { return p + "-" + uuid.NewString()[:8] }

func fixture(t *testing.T, s *store.Store) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	org, err := s.CreateOrganization(ctx, "AuditPkg", slug("auditpkg"))
	require.NoError(t, err)
	now := time.Now().UTC()
	r1, err := s.SubmitRun(ctx, store.SubmitRunParams{
		OrgID: org.ID, Source: store.RunSourceAgent,
		StartedAt: now.Add(-2 * time.Minute), CompletedAt: now.Add(-2 * time.Minute),
		Summary:  []byte(`{"pass":1}`),
		Findings: []byte(`[{"control_id":"a","status":"pass"}]`),
	})
	require.NoError(t, err)
	r2, err := s.SubmitRun(ctx, store.SubmitRunParams{
		OrgID: org.ID, Source: store.RunSourceAgent,
		StartedAt: now, CompletedAt: now,
		Summary:  []byte(`{"pass":0,"fail":1}`),
		Findings: []byte(`[{"control_id":"a","status":"fail","messages":["bad config"]}]`),
	})
	require.NoError(t, err)
	require.NoError(t, s.RecordDriftEvents(ctx, []store.RecordDriftEventParams{{
		OrgID: org.ID, RunID: r2.ID, PriorRunID: &r1.ID,
		ControlID: "a", From: "pass", To: "fail", Rationale: "bad config",
	}}))
	for i := 0; i < 2; i++ {
		s.RecordAudit(ctx, store.RecordAuditParams{
			ActorKind: store.AuditActorSystem,
			OrgID:     &org.ID,
			Action:    fmt.Sprintf("fixture.event.%d", i),
		})
	}
	return org.ID, r1.ID, r2.ID
}

func readZip(t *testing.T, buf *bytes.Buffer) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err, "the bundle must be a structurally valid ZIP — otherwise the auditor's tooling will reject it")
	out := make(map[string][]byte, len(zr.File))
	for _, f := range zr.File {
		rc, err := f.Open()
		require.NoError(t, err)
		body, err := io.ReadAll(rc)
		rc.Close()
		require.NoError(t, err)
		out[filepath.ToSlash(f.Name)] = body
	}
	return out
}

func TestBuild_ProducesEveryExpectedSection(t *testing.T) {
	s := openTestStore(t)
	orgID, r1, r2 := fixture(t, s)
	_, _, _ = orgID, r1, r2

	var buf bytes.Buffer
	meta, err := auditpackage.Build(context.Background(), s, orgID, auditpackage.Options{
		RequestedBy: "auditor@example.test",
	}, &buf)
	require.NoError(t, err)
	files := readZip(t, &buf)

	for _, name := range []string{
		"metadata.json",
		"findings/latest.json",
		"findings/latest-summary.json",
		"findings/latest-run.json",
		"runs.csv",
		"audit-events.csv",
		"drift-events.csv",
		"controls-overrides.json",
	} {
		assert.Containsf(t, files, name,
			"audit-package must include %s — downstream auditor tooling expects this layout", name)
	}

	var got auditpackage.Metadata
	require.NoError(t, json.Unmarshal(files["metadata.json"], &got))
	assert.Equal(t, "auditor@example.test", got.RequestedBy,
		"requested_by must surface in metadata so the bundle is attributable")
	assert.True(t, got.Counts.HasFindings)
	assert.Equal(t, 2, got.Counts.Runs)
	assert.Equal(t, 1, got.Counts.DriftEvents)
	assert.GreaterOrEqual(t, got.Counts.AuditEvents, 2,
		"audit-events.csv must include at least the fixtures we wrote")
	assert.Equal(t, meta, got,
		"the Metadata returned to the caller must match what's serialized into metadata.json")
}

func TestBuild_LatestFindingsArrayIsTheNewestSucceededRun(t *testing.T) {
	s := openTestStore(t)
	orgID, _, r2 := fixture(t, s)

	var buf bytes.Buffer
	_, err := auditpackage.Build(context.Background(), s, orgID, auditpackage.Options{}, &buf)
	require.NoError(t, err)
	files := readZip(t, &buf)

	var latest map[string]any
	require.NoError(t, json.Unmarshal(files["findings/latest-run.json"], &latest))
	assert.Equal(t, r2.String(), latest["run_id"],
		"findings/latest-run.json must point at the newest succeeded run — auditors take that as the point-in-time evidence")

	var findings []map[string]any
	require.NoError(t, json.Unmarshal(files["findings/latest.json"], &findings))
	require.Len(t, findings, 1)
	assert.Equal(t, "fail", findings[0]["status"])
}

func TestBuild_HandlesOrgWithNoSucceededRuns(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, err := s.CreateOrganization(ctx, "Empty", slug("empty"))
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = auditpackage.Build(ctx, s, org.ID, auditpackage.Options{}, &buf)
	require.NoError(t, err)
	files := readZip(t, &buf)

	require.Contains(t, files, "metadata.json")
	_, hasFindings := files["findings/latest.json"]
	assert.False(t, hasFindings,
		"a brand-new org with no runs must skip the findings section — empty findings would be misleading evidence")

	var meta auditpackage.Metadata
	require.NoError(t, json.Unmarshal(files["metadata.json"], &meta))
	assert.False(t, meta.Counts.HasFindings)
	assert.Equal(t, 0, meta.Counts.Runs)
}

func TestBuild_RunsCSVHasCanonicalHeaderAndRows(t *testing.T) {
	s := openTestStore(t)
	orgID, _, _ := fixture(t, s)
	var buf bytes.Buffer
	_, err := auditpackage.Build(context.Background(), s, orgID, auditpackage.Options{}, &buf)
	require.NoError(t, err)
	files := readZip(t, &buf)

	rdr := csv.NewReader(bytes.NewReader(files["runs.csv"]))
	rows, err := rdr.ReadAll()
	require.NoError(t, err, "runs.csv must be valid CSV")
	require.NotEmpty(t, rows)
	assert.Equal(t,
		[]string{"id", "status", "source", "started_at", "completed_at",
			"error_message", "agent_version",
			"triggered_by_token", "triggered_by_user"},
		rows[0],
		"runs.csv header order is part of the wire contract — bump format_version in metadata.json before changing it")
	assert.Greater(t, len(rows), 1, "the body must have at least one run row")
}

func TestBuild_ContextCancellationAbortsPromptly(t *testing.T) {
	s := openTestStore(t)
	orgID, _, _ := fixture(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var buf bytes.Buffer
	_, err := auditpackage.Build(ctx, s, orgID, auditpackage.Options{}, &buf)
	assert.Error(t, err,
		"a pre-cancelled context must short-circuit Build — otherwise a client disconnect leaves the server burning cycles to write to nowhere")
}

func TestBuild_WindowFiltersApplyToAuditAndDriftSections(t *testing.T) {
	s := openTestStore(t)
	orgID, _, _ := fixture(t, s)

	future := time.Now().UTC().Add(24 * time.Hour)
	var buf bytes.Buffer
	_, err := auditpackage.Build(context.Background(), s, orgID, auditpackage.Options{
		Since: future,
	}, &buf)
	require.NoError(t, err)
	files := readZip(t, &buf)

	rdr := csv.NewReader(bytes.NewReader(files["audit-events.csv"]))
	rows, _ := rdr.ReadAll()
	assert.Equal(t, 1, len(rows),
		"audit-events.csv must contain only the header when since= excludes every event — proves the filter wires through")
	assert.True(t, strings.HasPrefix(string(files["audit-events.csv"]), "id,"),
		"header must still be present so downstream parsers don't choke on an empty file")
}
