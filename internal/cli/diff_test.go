package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/watcher"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func writeFindingsArray(t *testing.T, dir, name string, findings []apiv1.Finding) string {
	t.Helper()
	path := filepath.Join(dir, name)
	raw, err := json.Marshal(findings)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o644))
	return path
}

func TestLoadFindings_AcceptsBareArray(t *testing.T) {
	dir := t.TempDir()
	path := writeFindingsArray(t, dir, "bare.json", []apiv1.Finding{{ControlID: "X", Status: apiv1.StatusPass}})
	got, err := loadFindings(path)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestLoadFindings_AcceptsJSONReportEnvelope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "envelope.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
		"summary": {"pass": 1, "fail": 0},
		"findings": [{"control_id": "Y", "status": "pass"}]
	}`), 0o644))
	got, err := loadFindings(path)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "Y", got[0].ControlID)
}

func TestRenderDiffMarkdown_GroupsByCategory(t *testing.T) {
	baseline := []apiv1.Finding{
		{ControlID: "REG-1", Title: "Branch protection", Status: apiv1.StatusPass},
		{ControlID: "REM-1", Title: "MFA enrollment", Status: apiv1.StatusFail},
		{ControlID: "GONE-1", Title: "Retired", Status: apiv1.StatusPass},
	}
	current := []apiv1.Finding{
		{ControlID: "REG-1", Title: "Branch protection", Status: apiv1.StatusFail},
		{ControlID: "REM-1", Title: "MFA enrollment", Status: apiv1.StatusPass},
		{ControlID: "NEW-1", Title: "New control | with pipe", Status: apiv1.StatusPass},
	}
	events := watcher.Diff(baseline, current, time.Now().UTC())

	var buf bytes.Buffer
	renderDiffMarkdown(&buf, "baseline.json", "current.json", baseline, current, events)
	out := buf.String()

	assert.Contains(t, out, "# Concord drift report")
	assert.Contains(t, out, "## 🚨 Regressions (1)")
	assert.Contains(t, out, "`REG-1`")
	assert.Contains(t, out, "## ✅ Remediated (1)")
	assert.Contains(t, out, "`REM-1`")
	assert.Contains(t, out, "## ➕ Added controls (1)")
	assert.Contains(t, out, "`NEW-1`")
	assert.Contains(t, out, "## ➖ Removed controls (1)")
	assert.Contains(t, out, "`GONE-1`")

	assert.Contains(t, out, `New control \| with pipe`)
	assert.NotContains(t, out, "| New control | with pipe |", "raw pipe would break the table")
}

func TestRenderDiffMarkdown_NoDriftEmitsConciseSummary(t *testing.T) {
	identical := []apiv1.Finding{{ControlID: "X", Status: apiv1.StatusPass}}
	events := watcher.Diff(identical, identical, time.Now().UTC())

	var buf bytes.Buffer
	renderDiffMarkdown(&buf, "a.json", "b.json", identical, identical, events)
	out := buf.String()
	assert.Contains(t, out, "_No drift — every control's status is unchanged._")
	assert.NotContains(t, out, "Regressions")
}

func TestHasRegression(t *testing.T) {
	assert.True(t, hasRegression([]watcher.Event{{Reason: "regression"}}))
	assert.True(t, hasRegression([]watcher.Event{{Reason: "evaluation error"}}))
	assert.False(t, hasRegression([]watcher.Event{{Reason: "remediated"}, {Reason: "new control added since last run"}}))
}

func TestLoadFindings_InvalidJSONErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.json")
	require.NoError(t, os.WriteFile(path, []byte("{ this is not json"), 0o644))
	_, err := loadFindings(path)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "parsing") || strings.Contains(err.Error(), "invalid"))
}
