package cli

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleInventory = `apiVersion: concord.dev/v1
kind: AISystemInventory
spec:
  systems:
    - id: fraud-detector
      name: Fraud Detection Model
      risk_class: high-risk
      environment: production
      owner: ml-platform
      tags: [payments]
    - id: doc-summarizer
      name: Doc Summarizer
      risk_class: limited
`

func TestParseAISystems_Valid(t *testing.T) {
	inv, err := parseAISystems([]byte(sampleInventory))
	require.NoError(t, err)
	require.Len(t, inv.Spec.Systems, 2)
	assert.Equal(t, "fraud-detector", inv.Spec.Systems[0].ID)
	assert.Equal(t, "high-risk", inv.Spec.Systems[0].RiskClass)
}

func TestParseAISystems_Rejects(t *testing.T) {
	cases := map[string]string{
		"wrong kind": "kind: Nope\nspec:\n  systems: [{id: a, name: A, risk_class: limited}]\n",
		"no systems": "kind: AISystemInventory\nspec:\n  systems: []\n",
		"missing id": "kind: AISystemInventory\nspec:\n  systems: [{name: A, risk_class: limited}]\n",
		"bad class":  "kind: AISystemInventory\nspec:\n  systems: [{id: a, name: A, risk_class: sorta-risky}]\n",
		"duplicate":  "kind: AISystemInventory\nspec:\n  systems: [{id: a, name: A, risk_class: limited},{id: a, name: B, risk_class: minimal}]\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseAISystems([]byte(body))
			assert.Error(t, err)
		})
	}
}

func TestAISystemsToAssetCSV(t *testing.T) {
	inv, err := parseAISystems([]byte(sampleInventory))
	require.NoError(t, err)
	out, err := aiSystemsToAssetCSV(inv)
	require.NoError(t, err)

	r := csv.NewReader(strings.NewReader(string(out)))
	rows, err := r.ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 3, "header + 2 systems")
	assert.Equal(t, []string{"type", "name", "external_id", "source", "criticality", "environment", "tags"}, rows[0])

	// high-risk fraud-detector → ai_model, criticality 1, eu_ai_act_tier:high tag.
	fd := rows[1]
	assert.Equal(t, "ai_model", fd[0])
	assert.Equal(t, "fraud-detector", fd[2])
	assert.Equal(t, "ai-systems", fd[3])
	assert.Equal(t, "1", fd[4])
	assert.Equal(t, "production", fd[5])
	assert.Contains(t, fd[6], "eu_ai_act_tier:high")
	assert.Contains(t, fd[6], "owner:ml-platform")
	assert.Contains(t, fd[6], "payments")

	// limited doc-summarizer → criticality 2, eu_ai_act_tier:limited.
	ds := rows[2]
	assert.Equal(t, "2", ds[4])
	assert.Contains(t, ds[6], "eu_ai_act_tier:limited")
}
