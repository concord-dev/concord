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

const (
	euAct11Path = "controls/frameworks/eu-ai-act/article-11-technical-documentation.yaml"
	euAct13Path = "controls/frameworks/eu-ai-act/article-13-transparency.yaml"
	euAct14Path = "controls/frameworks/eu-ai-act/article-14-human-oversight.yaml"
)


func TestRunEUAct11_Pass(t *testing.T) {
	f := runMultiFixture(t, euAct11Path, map[string]string{
		"model_registry": "models-with-high-risk.json",
		"technical_docs": "tech-docs-pass.json",
	})
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunEUAct11_MissingDocFails(t *testing.T) {
	f := runMultiFixture(t, euAct11Path, map[string]string{
		"model_registry": "models-with-high-risk.json",
		"technical_docs": "tech-docs-missing.json",
	})
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `high-risk model "fraud-detector" has no technical documentation under docs/ai/technical-documentation/`)
	for _, m := range f.Messages {
		assert.NotContains(t, m, "spam-classifier")
	}
}

func TestRunEUAct11_StaleDocFails(t *testing.T) {
	f := runMultiFixture(t, euAct11Path, map[string]string{
		"model_registry": "models-with-high-risk.json",
		"technical_docs": "tech-docs-stale.json",
	})
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `technical doc "docs/ai/technical-documentation/fraud-detector.md" has not been reviewed in over 180 days`)
}


func TestRunEUAct13_PassViaTag(t *testing.T) {
	f := runMultiFixture(t, euAct13Path, map[string]string{
		"model_registry": "models-with-high-risk.json",
		"model_cards":    "model-cards-empty.json", // no file needed when URL tag present
	})
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunEUAct13_PassViaFile(t *testing.T) {
	f := runMultiFixture(t, euAct13Path, map[string]string{
		"model_registry": "models-no-card-url.json",
		"model_cards":    "model-cards-pass.json",
	})
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v", f.Messages)
}

func TestRunEUAct13_FailsWhenNeitherPresent(t *testing.T) {
	f := runMultiFixture(t, euAct13Path, map[string]string{
		"model_registry": "models-no-card-url.json",
		"model_cards":    "model-cards-empty.json",
	})
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `high-risk model "fraud-detector" has neither public_model_card_url tag nor docs/ai/model-cards/<model>.md`)
}


func TestRunEUAct14_Pass(t *testing.T) {
	f := runMultiFixture(t, euAct14Path, map[string]string{
		"model_registry": "models-with-high-risk.json",
		"oversight_docs": "oversight-pass.json",
	})
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunEUAct14_MissingSectionFails(t *testing.T) {
	f := runMultiFixture(t, euAct14Path, map[string]string{
		"model_registry": "models-with-high-risk.json",
		"oversight_docs": "oversight-missing-sections.json",
	})
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `oversight runbook "docs/ai/oversight/fraud-detector.md" is missing required section "limitations"`)
	assert.Contains(t, f.Messages, `oversight runbook "docs/ai/oversight/fraud-detector.md" is missing required section "kill_switch"`)
}


func runMultiFixture(t *testing.T, controlRelPath string, fixtureByEvID map[string]string) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), controlRelPath)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)

	for i := range c.Spec.Evidence {
		if name, ok := fixtureByEvID[c.Spec.Evidence[i].ID]; ok {
			c.Spec.Evidence[i].Fixture = "./tests/fixtures/" + name
		}
	}

	r := New(policy.New(), evidence.NewFileCollector())
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
}
