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

// writeGenericPack lays down a pack with the given control body, rego, and
// slug-convention pass/fail fixtures, returning the control yaml path.
func writeGenericPack(t *testing.T, slug, controlBody, regoBody, passJSON, failJSON string) string {
	t.Helper()
	root := t.TempDir()
	mkdir(t, filepath.Join(root, "controls"))
	mkdir(t, filepath.Join(root, "policies"))
	mkdir(t, filepath.Join(root, "tests", "fixtures"))
	writeFile(t, filepath.Join(root, "controls", slug+".yaml"), controlBody)
	writeFile(t, filepath.Join(root, "policies", "p.rego"), regoBody)
	writeFile(t, filepath.Join(root, "tests", "fixtures", slug+"-pass.json"), passJSON)
	writeFile(t, filepath.Join(root, "tests", "fixtures", slug+"-fail.json"), failJSON)
	return filepath.Join(root, "controls", slug+".yaml")
}

func writeETNamed(t *testing.T, controlYAML, name, body string) {
	t.Helper()
	dir := filepath.Join(filepath.Dir(filepath.Dir(controlYAML)), "evidence-types")
	mkdir(t, dir)
	writeFile(t, filepath.Join(dir, name), body)
}

func TestValidateControl_SchemaCheck_EvidenceIDCollidesWithPayloadKey(t *testing.T) {
	// Single evidence whose id equals a top-level payload key ("data"); the
	// bare fixture must be validated whole, not by extracting parsed["data"].
	control := `apiVersion: concord.dev/v1
kind: Control
metadata: {id: COLL-1, name: coll, title: collision, framework: test, severity: high}
spec:
  description: id collides with a payload key.
  evidence:
    - id: data
      source: acme
      type: gadget
  policy: {engine: rego, package: concord.coll, file: ../policies/p.rego}
`
	rego := `package concord.coll
import rego.v1
deny contains msg if { input.data.label == "bad"; msg := "bad" }
`
	yamlPath := writeGenericPack(t, "coll-1", control, rego,
		`{"data": 5, "label": "ok"}`, `{"data": 5, "label": "bad"}`)
	writeETNamed(t, yamlPath, "gadget.yaml", `apiVersion: concord.dev/v1
kind: EvidenceType
metadata: {id: acme/gadget, version: v1.0.0}
spec:
  source: acme
  schema:
    type: object
    required: [data, label]
    properties:
      data: {type: integer}
      label: {type: string}
`)

	rep, err := scaffold.ValidateControl(context.Background(), yamlPath)
	require.NoError(t, err)
	require.Len(t, rep.SchemaChecks, 2, "one check per fixture")
	for _, sc := range rep.SchemaChecks {
		assert.True(t, sc.OK, "fixture %s must validate whole, not parsed[data]: %s", sc.Fixture, sc.Err)
	}
}

func TestValidateControl_SchemaCheck_MultiEvidenceWrapped(t *testing.T) {
	control := `apiVersion: concord.dev/v1
kind: Control
metadata: {id: MULTI-1, name: multi, title: multi, framework: test, severity: high}
spec:
  description: two evidence refs, wrapped fixture.
  evidence:
    - {id: e1, source: acme, type: alpha}
    - {id: e2, source: acme, type: beta}
  policy: {engine: rego, package: concord.multi, file: ../policies/p.rego}
`
	rego := `package concord.multi
import rego.v1
deny contains msg if { input.e1.ok == false; msg := "e1" }
deny contains msg if { input.e2.ok == false; msg := "e2" }
`
	yamlPath := writeGenericPack(t, "multi-1", control, rego,
		`{"e1": {"ok": true}, "e2": {"ok": true}}`,
		`{"e1": {"ok": false}, "e2": {"ok": true}}`)
	writeETNamed(t, yamlPath, "alpha.yaml", `apiVersion: concord.dev/v1
kind: EvidenceType
metadata: {id: acme/alpha, version: v1.0.0}
spec: {source: acme, schema: {type: object, required: [ok], properties: {ok: {type: boolean}}}}
`)
	writeETNamed(t, yamlPath, "beta.yaml", `apiVersion: concord.dev/v1
kind: EvidenceType
metadata: {id: acme/beta, version: v1.0.0}
spec: {source: acme, schema: {type: object, required: [ok], properties: {ok: {type: boolean}}}}
`)

	rep, err := scaffold.ValidateControl(context.Background(), yamlPath)
	require.NoError(t, err)
	require.NotEmpty(t, rep.SchemaChecks)
	for _, sc := range rep.SchemaChecks {
		assert.True(t, sc.OK, "wrapped payload %s should validate per-id: %s", sc.EvidenceID, sc.Err)
	}
	assert.True(t, rep.AllGreen())
}

func TestValidateControl_SchemaCheck_MultiEvidenceBareNoFalseFailure(t *testing.T) {
	// A bare fixture under a multi-evidence control cannot be attributed to a
	// single type; it must be skipped, never validated against every schema.
	control := `apiVersion: concord.dev/v1
kind: Control
metadata: {id: MULTIBARE-1, name: mb, title: mb, framework: test, severity: high}
spec:
  description: two evidence refs, bare fixture.
  evidence:
    - {id: e1, source: acme, type: alpha}
    - {id: e2, source: acme, type: beta}
  policy: {engine: rego, package: concord.mb, file: ../policies/p.rego}
`
	rego := `package concord.mb
import rego.v1
deny contains msg if { input.ok == false; msg := "x" }
`
	yamlPath := writeGenericPack(t, "multibare-1", control, rego, `{"ok": true}`, `{"ok": false}`)
	writeETNamed(t, yamlPath, "alpha.yaml", `apiVersion: concord.dev/v1
kind: EvidenceType
metadata: {id: acme/alpha, version: v1.0.0}
spec: {source: acme, schema: {type: object, required: [a], properties: {a: {type: string}}}}
`)
	writeETNamed(t, yamlPath, "beta.yaml", `apiVersion: concord.dev/v1
kind: EvidenceType
metadata: {id: acme/beta, version: v1.0.0}
spec: {source: acme, schema: {type: object, required: [b], properties: {b: {type: string}}}}
`)

	rep, err := scaffold.ValidateControl(context.Background(), yamlPath)
	require.NoError(t, err)
	assert.Empty(t, rep.SchemaChecks, "ambiguous bare multi-evidence fixture must be skipped, not false-failed")
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
