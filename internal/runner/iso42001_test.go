package runner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/policy"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
	"github.com/concord-dev/concord/pkg/controls"
)

const (
	iso42001Path        = "controls/frameworks/iso42001/6.1-ai-risk-assessment.yaml"
	iso42001EvalPath    = "controls/frameworks/iso42001/7.4-model-evaluation.yaml"
	iso42001DataQltPath = "controls/frameworks/iso42001/8.2-data-quality.yaml"
)

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

func TestRunISO42001_ModelEval_Pass(t *testing.T) {
	f := runISO42001Eval(t, "eval-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunISO42001_ModelEval_MissingReport(t *testing.T) {
	f := runISO42001Eval(t, "eval-missing-report.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `production model "fraud-detector" has no evaluation_report tag`)
}

func TestRunISO42001_ModelEval_Stale(t *testing.T) {
	f := runISO42001Eval(t, "eval-stale.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `production model "fraud-detector" was last evaluated over 90 days ago`)
}

func runISO42001Eval(t *testing.T, fixture string) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), iso42001EvalPath)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)
	c.Spec.Evidence[0].Fixture = "./tests/fixtures/" + fixture
	r := New(policy.New(), evidence.NewFileCollector())
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
}

func TestRunISO42001_DataQuality_Pass(t *testing.T) {
	f := runISO42001DataQuality(t, "data-quality-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunISO42001_DataQuality_MissingTagFails(t *testing.T) {
	f := runISO42001DataQuality(t, "data-quality-missing.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `production model "fraud-detector" has no dataset_card_url tag`)
}

func runISO42001DataQuality(t *testing.T, fixture string) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), iso42001DataQltPath)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)
	c.Spec.Evidence[0].Fixture = "./tests/fixtures/" + fixture
	r := New(policy.New(), evidence.NewFileCollector())
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
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
