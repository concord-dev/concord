package scaffold_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/scaffold"
)

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return string(b)
}

func TestConfig_WritesWhenMissing(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "concord.yaml")
	written, err := scaffold.Config(dest, false)
	require.NoError(t, err)
	assert.True(t, written)
	assert.Contains(t, readFile(t, dest), "apiVersion: concord.dev/v1")
}

func TestConfig_SkipsWhenExists(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "concord.yaml")
	require.NoError(t, os.WriteFile(dest, []byte("user-config"), 0o644))

	written, err := scaffold.Config(dest, false)
	require.NoError(t, err)
	assert.False(t, written)
	assert.Equal(t, "user-config", readFile(t, dest))
}

func TestGitHubAction_Writes(t *testing.T) {
	dest := filepath.Join(t.TempDir(), ".github", "workflows", "concord.yml")
	written, err := scaffold.GitHubAction(dest, false)
	require.NoError(t, err)
	assert.True(t, written)
	assert.Contains(t, readFile(t, dest), "concord check")
}

func TestControl_WritesYAMLRegoAndFixtures(t *testing.T) {
	dest := t.TempDir()
	r, err := scaffold.Control(dest, scaffold.ControlInput{
		Pack: "mycorp", ID: "MYCORP-1.1", Title: "Sample control",
		Framework: "mycorp", Severity: "high", Author: "platform",
	}, false)
	require.NoError(t, err)

	assert.FileExists(t, r.YAML)
	assert.FileExists(t, r.Rego)
	assert.FileExists(t, r.PassFix)
	assert.FileExists(t, r.FailFix)

	yaml := readFile(t, r.YAML)
	assert.Contains(t, yaml, "id: MYCORP-1.1")
	assert.Contains(t, yaml, "severity: high")
	assert.Contains(t, yaml, "package: concord.mycorp.mycorp_1_1")

	rego := readFile(t, r.Rego)
	assert.Contains(t, rego, "package concord.mycorp.mycorp_1_1")
	assert.Contains(t, rego, "import rego.v1")
}

func TestControl_RefusesToOverwriteWithoutForce(t *testing.T) {
	dest := t.TempDir()
	_, err := scaffold.Control(dest, scaffold.ControlInput{Pack: "p", ID: "X"}, false)
	require.NoError(t, err)

	_, err = scaffold.Control(dest, scaffold.ControlInput{Pack: "p", ID: "X"}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestControl_RequiresPackAndID(t *testing.T) {
	dest := t.TempDir()
	_, err := scaffold.Control(dest, scaffold.ControlInput{ID: "X"}, false)
	require.Error(t, err)
	_, err = scaffold.Control(dest, scaffold.ControlInput{Pack: "p"}, false)
	require.Error(t, err)
}
