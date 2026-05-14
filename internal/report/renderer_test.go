package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/report"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func sampleFindings() []apiv1.Finding {
	t0 := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	return []apiv1.Finding{
		{
			ControlID: "SOC2-CC8.1", Title: "Default branch is protected",
			Framework: "soc2", Severity: "high",
			Status:      apiv1.StatusPass,
			EvaluatedAt: t0, DurationMs: 3,
		},
		{
			ControlID: "ISO42001-6.1", Title: "AI risk assessment",
			Framework: "iso42001", Severity: "high",
			Status:      apiv1.StatusFail,
			Messages:    []string{"production model \"fraud-detector\" has no risk-assessment document"},
			Warnings:    []string{"high-risk model has no eval report"},
			EvaluatedAt: t0, DurationMs: 6,
		},
		{
			ControlID: "FAKE-1", Title: "Fake control",
			Framework: "fake", Severity: "low",
			Status:      apiv1.StatusError,
			Messages:    []string{"collector blew up"},
			EvaluatedAt: t0,
		},
	}
}

func TestSummarize(t *testing.T) {
	s := report.Summarize(sampleFindings())
	assert.Equal(t, 1, s.Pass)
	assert.Equal(t, 1, s.Fail)
	assert.Equal(t, 1, s.Err)
	assert.Equal(t, 1, s.Warn)
}

func TestRendererFor_UnknownFormatErrors(t *testing.T) {
	_, err := report.RendererFor("yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

func TestRendererFor_AcceptsAliases(t *testing.T) {
	for _, f := range []string{"", "text", "json", "oscal", "markdown", "md"} {
		_, err := report.RendererFor(f)
		require.NoError(t, err, "format %q", f)
	}
}

func TestTextRenderer(t *testing.T) {
	var buf bytes.Buffer
	s, err := report.TextRenderer{}.Render(&buf, sampleFindings())
	require.NoError(t, err)
	assert.Equal(t, 1, s.Fail)

	out := buf.String()
	assert.Contains(t, out, "SOC2-CC8.1")
	assert.Contains(t, out, "ISO42001-6.1")
	assert.Contains(t, out, "fraud-detector")
	assert.Contains(t, out, "passed")
	assert.Contains(t, out, "failed")
}

func TestJSONRenderer_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	_, err := report.JSONRenderer{}.Render(&buf, sampleFindings())
	require.NoError(t, err)

	var got report.JSONReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, 1, got.Summary.Pass)
	assert.Equal(t, 1, got.Summary.Fail)
	assert.Len(t, got.Findings, 3)
	assert.Equal(t, "SOC2-CC8.1", got.Findings[0].ControlID)
}

func TestOSCALRenderer_ProducesValidEnvelope(t *testing.T) {
	var buf bytes.Buffer
	_, err := report.OSCALRenderer{}.Render(&buf, sampleFindings())
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))

	results := got["assessment-results"].(map[string]any)
	assert.NotEmpty(t, results["uuid"])

	meta := results["metadata"].(map[string]any)
	assert.Equal(t, "1.1.2", meta["oscal-version"])

	rs := results["results"].([]any)
	require.Len(t, rs, 1)
	r0 := rs[0].(map[string]any)

	findings := r0["findings"].([]any)
	assert.Len(t, findings, 3)

	first := findings[0].(map[string]any)
	target := first["target"].(map[string]any)
	assert.Equal(t, "SOC2-CC8.1", target["target-id"])
	assert.Equal(t, "satisfied", target["status"].(map[string]any)["state"])

	second := findings[1].(map[string]any)
	secondTarget := second["target"].(map[string]any)
	assert.Equal(t, "not-satisfied", secondTarget["status"].(map[string]any)["state"])

	observations := r0["observations"].([]any)
	assert.GreaterOrEqual(t, len(observations), 2, "expected observations for fail + error findings")
}

func TestMarkdownRenderer(t *testing.T) {
	var buf bytes.Buffer
	_, err := report.MarkdownRenderer{}.Render(&buf, sampleFindings())
	require.NoError(t, err)

	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "# Concord Assessment Results"))
	assert.Contains(t, out, "## SOC2-CC8.1")
	assert.Contains(t, out, "## ISO42001-6.1")
	assert.Contains(t, out, "✅ PASS")
	assert.Contains(t, out, "❌ FAIL")
	assert.Contains(t, out, "fraud-detector")
}
