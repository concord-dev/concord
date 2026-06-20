package controls

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validYAML = `apiVersion: concord.dev/v1
kind: Control
metadata:
  id: TEST-1
  name: test
  title: Test Control
  framework: test
  severity: high
spec:
  description: A test control.
  evidence:
    - id: foo
      source: file
      fixture: ./fixtures/foo.json
  policy:
    engine: rego
    package: concord.test
    file: ./policies/test.rego
`

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.yaml")
	require.NoError(t, os.WriteFile(p, []byte(validYAML), 0o644))

	c, err := LoadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "TEST-1", c.Metadata.ID)
	assert.Equal(t, "high", c.Metadata.Severity)
	assert.Len(t, c.Spec.Evidence, 1)
	assert.Equal(t, "concord.test", c.Spec.Policy.Package)
}

func TestLoadFileRejectsMissingFields(t *testing.T) {
	dir := t.TempDir()
	bad := `apiVersion: concord.dev/v1
kind: Control
metadata:
  id: ""
  title: ""
  framework: ""
  severity: rainbow
spec:
  description: ""
  evidence: []
  policy:
    engine: rego
    package: ""
    file: ""
`
	p := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(p, []byte(bad), 0o644))

	_, err := LoadFile(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata.id is required")
	assert.Contains(t, err.Error(), "metadata.severity")
	assert.Contains(t, err.Error(), "spec.evidence")
}

func TestLoadSkipsSiblingEvidenceTypeKind(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.yaml"), []byte(validYAML), 0o644))
	// An EvidenceType doc co-located in the controls tree must be skipped,
	// not parsed as a control (which would fail validation).
	et := `apiVersion: concord.dev/v1
kind: EvidenceType
metadata:
  id: okta/users_mfa
  version: v1.0.0
spec:
  source: okta
  schema:
    type: object
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "users_mfa.yaml"), []byte(et), 0o644))

	loaded, err := Load(dir)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "TEST-1", loaded[0].Control.Metadata.ID)
}

func TestLoadSkipsPoliciesAndTestsDirs(t *testing.T) {
	dir := t.TempDir()
	framework := filepath.Join(dir, "frameworks", "test")
	require.NoError(t, os.MkdirAll(framework, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(framework, "x.yaml"), []byte(validYAML), 0o644))

	pdir := filepath.Join(framework, "policies")
	require.NoError(t, os.MkdirAll(pdir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pdir, "ignored.yaml"), []byte(validYAML), 0o644))

	tdir := filepath.Join(framework, "tests")
	require.NoError(t, os.MkdirAll(tdir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tdir, "ignored.yaml"), []byte(validYAML), 0o644))

	loaded, err := Load(dir)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "TEST-1", loaded[0].Control.Metadata.ID)
}
