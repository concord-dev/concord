package scaffold_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/scaffold"
)

func TestControl_TemplateAWSResourceEmitsAWSEvidenceShape(t *testing.T) {
	dest := t.TempDir()
	r, err := scaffold.Control(dest, scaffold.ControlInput{
		Pack: "mycorp", ID: "MYCORP-AWS-1", Template: scaffold.TemplateAWSResource,
	}, false)
	require.NoError(t, err)

	yaml := readFile(t, r.YAML)
	assert.Contains(t, yaml, "source: aws")
	assert.Contains(t, yaml, "type: aws_resource_inventory")

	rego := readFile(t, r.Rego)
	assert.Contains(t, rego, "import data.concord.lib.evidence")
	assert.Contains(t, rego, ".resources")
	assert.Contains(t, rego, "arn")

	var pass map[string]any
	require.NoError(t, json.Unmarshal([]byte(readFile(t, r.PassFix)), &pass))
	var fail map[string]any
	require.NoError(t, json.Unmarshal([]byte(readFile(t, r.FailFix)), &fail))
}

func TestControl_TemplatePolicyAttestationEmitsAttestationShape(t *testing.T) {
	dest := t.TempDir()
	r, err := scaffold.Control(dest, scaffold.ControlInput{
		Pack: "gdpr", ID: "GDPR-30", Template: scaffold.TemplatePolicyAttestation,
	}, false)
	require.NoError(t, err)

	yaml := readFile(t, r.YAML)
	assert.Contains(t, yaml, "source: attestation")
	assert.Contains(t, yaml, "type: policy_attestation")
	assert.Contains(t, yaml, "signers")

	rego := readFile(t, r.Rego)
	assert.Contains(t, rego, "import data.concord.lib.attestation")
	assert.Contains(t, rego, "not_expired")
	assert.Contains(t, rego, "fresh")
}

func TestControl_EmitsLibHelperFiles(t *testing.T) {
	dest := t.TempDir()
	r, err := scaffold.Control(dest, scaffold.ControlInput{
		Pack: "mycorp", ID: "M-1", Template: scaffold.TemplateGeneric,
	}, false)
	require.NoError(t, err)

	require.NotEmpty(t, r.LibFiles, "lib helpers must be emitted")
	assert.FileExists(t, filepath.Join(dest, "policies", "lib", "evidence.rego"))
	assert.FileExists(t, filepath.Join(dest, "policies", "lib", "collection.rego"))
	assert.FileExists(t, filepath.Join(dest, "policies", "lib", "attestation.rego"))

	body := readFile(t, filepath.Join(dest, "policies", "lib", "collection.rego"))
	assert.Contains(t, body, "package concord.lib.collection")
	assert.Contains(t, body, "all_compliant(items)")
}

func TestControl_LibFilesIdempotentAcrossControls(t *testing.T) {
	dest := t.TempDir()
	_, err := scaffold.Control(dest, scaffold.ControlInput{Pack: "p", ID: "A"}, false)
	require.NoError(t, err)
	_, err = scaffold.Control(dest, scaffold.ControlInput{Pack: "p", ID: "B"}, false)
	require.NoError(t, err, "second control should not error on pre-existing lib files")

	assert.FileExists(t, filepath.Join(dest, "policies", "lib", "evidence.rego"))
}

func TestParseTemplate_RejectsUnknown(t *testing.T) {
	_, err := scaffold.ParseTemplate("bogus")
	require.Error(t, err)
}

func TestParseTemplate_EmptyDefaultsToGeneric(t *testing.T) {
	tmpl, err := scaffold.ParseTemplate("")
	require.NoError(t, err)
	assert.Equal(t, scaffold.TemplateGeneric, tmpl)
}
