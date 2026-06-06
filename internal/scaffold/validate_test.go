package scaffold_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/scaffold"
)

func TestValidateControl_AWSTemplateRoundtrip(t *testing.T) {
	dest := t.TempDir()
	_, err := scaffold.Control(dest, scaffold.ControlInput{
		Pack: "mycorp", ID: "MYCORP-AWS-1", Template: scaffold.TemplateAWSResource,
	}, false)
	require.NoError(t, err)

	yamlPath := filepath.Join(dest, "controls", "mycorp-aws-1.yaml")
	rep, err := scaffold.ValidateControl(context.Background(), yamlPath)
	require.NoError(t, err)

	if !rep.AllGreen() {
		t.Fatalf("validation not green: errors=%v pass=%+v fail=%+v",
			rep.Errors, rep.PassResult, rep.FailResult)
	}
	assert.Equal(t, "MYCORP-AWS-1", rep.ControlID)
	require.NotNil(t, rep.PassResult)
	require.NotNil(t, rep.FailResult)
	assert.True(t, rep.PassResult.Pass)
	assert.False(t, rep.FailResult.Pass)
	assert.NotEmpty(t, rep.FailResult.Deny, "fail fixture should produce deny messages")
}

func TestValidateControl_PolicyAttestationRoundtrip(t *testing.T) {
	dest := t.TempDir()
	_, err := scaffold.Control(dest, scaffold.ControlInput{
		Pack: "gdpr", ID: "GDPR-30", Template: scaffold.TemplatePolicyAttestation,
	}, false)
	require.NoError(t, err)

	yamlPath := filepath.Join(dest, "controls", "gdpr-30.yaml")
	rep, err := scaffold.ValidateControl(context.Background(), yamlPath)
	require.NoError(t, err)
	if !rep.AllGreen() {
		t.Fatalf("validation not green: errors=%v pass=%+v fail=%+v",
			rep.Errors, rep.PassResult, rep.FailResult)
	}
}

func TestValidateControl_MissingFixturesReportsError(t *testing.T) {
	dest := t.TempDir()
	_, err := scaffold.Control(dest, scaffold.ControlInput{Pack: "p", ID: "X"}, false)
	require.NoError(t, err)

	// Delete the fail fixture and confirm validation flags it.
	require.NoError(t, removeFile(filepath.Join(dest, "tests", "fixtures", "x-fail.json")))

	yamlPath := filepath.Join(dest, "controls", "x.yaml")
	rep, err := scaffold.ValidateControl(context.Background(), yamlPath)
	require.NoError(t, err)
	assert.False(t, rep.AllGreen())
	require.NotEmpty(t, rep.Errors)
}

func removeFile(p string) error { return removeFileImpl(p) }
