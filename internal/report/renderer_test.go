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
			Status: apiv1.StatusPass,
			Mappings: map[string][]string{
				"iso27001": {"A.8.30", "A.8.32"},
				"nist_csf": {"PR.IP-3"},
			},
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
	_, err := report.RendererFor("yaml", report.Opts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

func TestRendererFor_AcceptsAliases(t *testing.T) {
	for _, f := range []string{"", "text", "json", "oscal", "markdown", "md", "trust-portal"} {
		_, err := report.RendererFor(f, report.Opts{})
		require.NoError(t, err, "format %q", f)
	}
}

// TestTrustPortal_DoesNotLeakInternalEvidence is the security-critical test
// for the trust portal. The page is public — it MUST NOT include deny messages
// (which contain internal names, emails, bucket names, model IDs, etc.).
func TestTrustPortal_DoesNotLeakInternalEvidence(t *testing.T) {
	var buf bytes.Buffer
	r := report.TrustPortalRenderer{OrgName: "Concord Inc."}
	_, err := r.Render(&buf, sampleFindings())
	require.NoError(t, err)

	out := buf.String()
	// Org name and public control metadata must appear.
	assert.Contains(t, out, "Concord Inc.")
	assert.Contains(t, out, "SOC 2 Type I")
	assert.Contains(t, out, "SOC2-CC8.1")
	assert.Contains(t, out, "Compliant")
	assert.Contains(t, out, "Gap identified")

	// CRITICAL: deny messages (with internal details) must NOT appear.
	for _, sensitive := range []string{
		"fraud-detector",                 // from f.Messages
		"production model",               // from f.Messages
		"collector blew up",              // from f.Messages on error finding
		"high-risk model has no eval",    // from f.Warnings
	} {
		assert.NotContains(t, out, sensitive, "internal evidence leaked into trust portal: %q", sensitive)
	}
}

func TestTrustPortal_FallsBackOnEmptyOrgName(t *testing.T) {
	var buf bytes.Buffer
	r := report.TrustPortalRenderer{} // OrgName left blank
	_, err := r.Render(&buf, sampleFindings())
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Your Organization")
}

func TestTrustPortal_ProducesValidHTML(t *testing.T) {
	var buf bytes.Buffer
	r := report.TrustPortalRenderer{OrgName: "Test"}
	_, err := r.Render(&buf, sampleFindings())
	require.NoError(t, err)
	out := buf.String()
	// Basic structural assertions — full HTML validation would need a parser.
	assert.True(t, strings.HasPrefix(out, "<!DOCTYPE html>"), "must start with doctype")
	assert.Contains(t, out, "<html")
	assert.Contains(t, out, "</html>")
	assert.Contains(t, out, "<title>")
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

	// Crosswalk: SOC2-CC8.1 has mappings to iso27001 and nist_csf — both should appear as props.
	props := first["props"].([]any)
	var mappedValues []string
	for _, p := range props {
		pm := p.(map[string]any)
		if pm["name"] == "mapped-control" {
			mappedValues = append(mappedValues, pm["value"].(string))
		}
	}
	assert.Contains(t, mappedValues, "iso27001:A.8.30")
	assert.Contains(t, mappedValues, "iso27001:A.8.32")
	assert.Contains(t, mappedValues, "nist_csf:PR.IP-3")
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
