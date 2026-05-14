package runner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/policy"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const iso42001Path = "controls/frameworks/iso42001/6.1-ai-risk-assessment.yaml"

func TestRunISO42001Pass(t *testing.T) {
	f := runISO42001(t, "models-baseline.json", "docs-baseline.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
	assert.Empty(t, f.Messages)
	assert.Empty(t, f.Warnings, "baseline should not produce warnings")
}

func TestRunISO42001MissingRiskDoc(t *testing.T) {
	f := runISO42001(t, "models-baseline.json", "docs-missing-fraud-detector.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `production model "fraud-detector" has no risk-assessment document`)
}

func TestRunISO42001NoReviewer(t *testing.T) {
	f := runISO42001(t, "models-baseline.json", "docs-no-reviewer.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `risk doc "docs/ai/risk-assessments/fraud-detector.md" has no human reviewer`)
}

func TestRunISO42001MissingField(t *testing.T) {
	f := runISO42001(t, "models-baseline.json", "docs-missing-field.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `risk doc "docs/ai/risk-assessments/fraud-detector.md" is missing required field "foreseeable_misuse"`)
}

func TestRunISO42001InvalidTier(t *testing.T) {
	f := runISO42001(t, "models-invalid-tier.json", "docs-baseline.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `model "fraud-detector" has invalid EU AI Act tier "uncertain" (must be one of minimal|limited|high|prohibited)`)
}

func TestRunISO42001ProhibitedInProd(t *testing.T) {
	f := runISO42001(t, "models-prohibited-in-prod.json", "docs-baseline.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `model "fraud-detector" is classified prohibited under EU AI Act but is running in production`)
}

func TestRunISO42001Stale(t *testing.T) {
	f := runISO42001(t, "models-baseline.json", "docs-stale.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `risk doc "docs/ai/risk-assessments/fraud-detector.md" has not been reviewed in over 365 days`)
}

func runISO42001(t *testing.T, modelsFixture, docsFixture string) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), iso42001Path)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)

	for i := range c.Spec.Evidence {
		switch c.Spec.Evidence[i].ID {
		case "model_registry":
			c.Spec.Evidence[i].Fixture = "./tests/fixtures/" + modelsFixture
		case "risk_assessments":
			c.Spec.Evidence[i].Fixture = "./tests/fixtures/" + docsFixture
		}
	}

	r := New(policy.New(), evidence.NewFileCollector())
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
}
