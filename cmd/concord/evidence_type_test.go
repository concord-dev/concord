package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const repoEvidenceType = "../../controls/evidence-types/okta_users_mfa.yaml"
const repoOktaFixture = "testdata/okta-pass.json"

func runEvidenceType(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newEvidenceTypeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestEvidenceTypeValidate_ExampleIsValid(t *testing.T) {
	require.FileExists(t, repoEvidenceType)
	_, err := runEvidenceType(t, "validate", repoEvidenceType)
	require.NoError(t, err)
}

func TestEvidenceTypeCheck_RealFixtureIsValid(t *testing.T) {
	require.FileExists(t, repoOktaFixture)
	_, err := runEvidenceType(t, "check", repoEvidenceType, repoOktaFixture)
	require.NoError(t, err)
}

func TestEvidenceTypeCheck_BadPayloadFails(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	// Missing the required "users" array.
	require.NoError(t, os.WriteFile(bad, []byte(`{"fetched_at":"2026-01-01T00:00:00Z"}`), 0o644))

	_, err := runEvidenceType(t, "check", repoEvidenceType, bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "INVALID")
}

func TestEvidenceTypeValidate_RejectsBadFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("kind: EvidenceType\nmetadata:\n  id: x/y\n"), 0o644))

	_, err := runEvidenceType(t, "validate", bad)
	require.Error(t, err)
}

func TestEvidenceTypeList_FindsExample(t *testing.T) {
	out, err := runEvidenceType(t, "list", filepath.Dir(repoEvidenceType))
	require.NoError(t, err)
	assert.Contains(t, out, "okta/users_mfa")
}
