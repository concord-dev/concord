package scaffold_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/scaffold"
)

// A multi-evidence control can't be replayed from a single evidence's fixture
// (the Rego needs every evidence id present at once). ValidateControl must use
// the combined wrapped <slug>-{pass,fail}.json fixture for it.
func TestValidateControl_MultiEvidenceUsesCombinedFixture(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"controls", "policies", filepath.Join("tests", "fixtures")} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
	}
	writeFile(t, filepath.Join(dir, "controls", "multi.yaml"), `apiVersion: concord.dev/v1
kind: Control
metadata:
  id: TEST-MULTI-1
  name: multi-evidence
  title: Multi-evidence control
  framework: test
  severity: high
spec:
  description: needs two evidence sources at once
  evidence:
    - id: registry
      source: mlflow
      type: model_registry
      fixture: ../tests/fixtures/ignored-a.json
    - id: docs
      source: github
      type: file_glob
      fixture: ../tests/fixtures/ignored-b.json
  policy:
    engine: rego
    package: concord.test.multi
    file: ../policies/multi.rego
  status: stable
`)
	writeFile(t, filepath.Join(dir, "policies", "multi.rego"), `package concord.test.multi

import rego.v1

deny contains msg if {
	not input.registry
	msg := "no registry evidence"
}

deny contains msg if {
	not input.docs
	msg := "no docs evidence"
}

deny contains msg if {
	input.docs.ok != true
	msg := "docs not ok"
}
`)
	// Combined wrapped fixtures — top-level keys are the evidence ids.
	writeFile(t, filepath.Join(dir, "tests", "fixtures", "multi-pass.json"),
		`{"registry": {"models": []}, "docs": {"ok": true}}`)
	writeFile(t, filepath.Join(dir, "tests", "fixtures", "multi-fail.json"),
		`{"registry": {"models": []}, "docs": {"ok": false}}`)

	rep, err := scaffold.ValidateControl(context.Background(), filepath.Join(dir, "controls", "multi.yaml"))
	require.NoError(t, err)
	if !rep.AllGreen() {
		t.Fatalf("multi-evidence validation not green: errors=%v pass=%+v fail=%+v",
			rep.Errors, rep.PassResult, rep.FailResult)
	}
	assert.Contains(t, rep.PassFixture, "multi-pass.json", "must select the combined pass fixture")
	assert.Contains(t, rep.FailFixture, "multi-fail.json")
	require.NotNil(t, rep.FailResult)
	assert.Contains(t, rep.FailResult.Deny, "docs not ok")
}
