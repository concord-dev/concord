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

// writePack lays down a minimal pack (control + rego + pass/fail fixtures)
// in the layout ValidateControl expects, and returns the control yaml path.
func writePack(t *testing.T, evidenceType string) string {
	t.Helper()
	root := t.TempDir()
	mkdir(t, filepath.Join(root, "controls"))
	mkdir(t, filepath.Join(root, "policies"))
	mkdir(t, filepath.Join(root, "tests", "fixtures"))

	control := `apiVersion: concord.dev/v1
kind: Control
metadata:
  id: ET-1
  name: et-test
  title: Evidence-type wiring test
  framework: test
  severity: high
spec:
  description: validates evidence payloads against an EvidenceType schema.
  evidence:
    - id: e1
      source: acme
      type: ` + evidenceType + `
      fixture: ../tests/fixtures/et-1-pass.json
  policy:
    engine: rego
    package: concord.ettest
    file: ../policies/et_1.rego
`
	writeFile(t, filepath.Join(root, "controls", "et-1.yaml"), control)

	rego := `package concord.ettest
import rego.v1
deny contains msg if {
	input.e1.ok == false
	msg := "not ok"
}
`
	writeFile(t, filepath.Join(root, "policies", "et_1.rego"), rego)
	writeFile(t, filepath.Join(root, "tests", "fixtures", "et-1-pass.json"), `{"ok": true, "count": 5}`)
	writeFile(t, filepath.Join(root, "tests", "fixtures", "et-1-fail.json"), `{"ok": false, "count": 5}`)
	return filepath.Join(root, "controls", "et-1.yaml")
}

func writeEvidenceType(t *testing.T, controlYAML, body string) {
	t.Helper()
	packDir := filepath.Dir(filepath.Dir(controlYAML))
	dir := filepath.Join(packDir, "evidence-types")
	mkdir(t, dir)
	writeFile(t, filepath.Join(dir, "acme.yaml"), body)
}

func TestValidateControl_SchemaCheckPasses(t *testing.T) {
	yamlPath := writePack(t, "widget_config")
	writeEvidenceType(t, yamlPath, `apiVersion: concord.dev/v1
kind: EvidenceType
metadata:
  id: acme/widget_config
  version: v1.0.0
spec:
  source: acme
  schema:
    type: object
    required: [ok, count]
    properties:
      ok: {type: boolean}
      count: {type: integer}
`)

	rep, err := scaffold.ValidateControl(context.Background(), yamlPath)
	require.NoError(t, err)
	require.NotEmpty(t, rep.SchemaChecks, "schema checks should run when an EvidenceType is registered")
	for _, sc := range rep.SchemaChecks {
		assert.True(t, sc.OK, "fixture %s should be schema-valid: %s", sc.Fixture, sc.Err)
		assert.Equal(t, "acme/widget_config", sc.TypeRef)
	}
	assert.True(t, rep.AllGreen())
}

func TestValidateControl_SchemaCheckCatchesDrift(t *testing.T) {
	yamlPath := writePack(t, "widget_config")
	// The schema requires a field the fixtures don't have — the fixture has
	// drifted from the declared contract.
	writeEvidenceType(t, yamlPath, `apiVersion: concord.dev/v1
kind: EvidenceType
metadata:
  id: acme/widget_config
  version: v1.0.0
spec:
  source: acme
  schema:
    type: object
    required: [ok, region]
    properties:
      ok: {type: boolean}
      region: {type: string}
`)

	rep, err := scaffold.ValidateControl(context.Background(), yamlPath)
	require.NoError(t, err)
	require.NotEmpty(t, rep.SchemaChecks)
	var sawInvalid bool
	for _, sc := range rep.SchemaChecks {
		if !sc.OK {
			sawInvalid = true
		}
	}
	assert.True(t, sawInvalid, "expected a schema check to fail on the drifted fixture")
	assert.False(t, rep.AllGreen(), "schema drift must fail validation")
}

func TestValidateControl_NoEvidenceTypeSkipsSchemaChecks(t *testing.T) {
	yamlPath := writePack(t, "widget_config")
	// No evidence-types/ dir at all — schema checks are opt-in and must not
	// run or affect the result.
	rep, err := scaffold.ValidateControl(context.Background(), yamlPath)
	require.NoError(t, err)
	assert.Empty(t, rep.SchemaChecks)
	assert.True(t, rep.AllGreen())
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(p, 0o755))
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
}
