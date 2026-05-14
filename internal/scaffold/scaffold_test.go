package scaffold_test

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/scaffold"
)

func newMockFS() fstest.MapFS {
	return fstest.MapFS{
		"controls/frameworks/soc2/cc1.yaml":              {Data: []byte("soc2-cc1")},
		"controls/frameworks/soc2/policies/cc1.rego":     {Data: []byte("rego-cc1")},
		"controls/frameworks/soc2/tests/fixtures/p.json": {Data: []byte(`{"a":1}`)},
		"controls/frameworks/iso42001/r.yaml":            {Data: []byte("iso42001-r")},
		"controls/frameworks/iso42001/policies/r.rego":   {Data: []byte("rego-r")},
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return string(b)
}

func TestFrameworks_CopiesAll(t *testing.T) {
	dest := t.TempDir()
	r, err := scaffold.Frameworks(newMockFS(), dest, nil, false)
	require.NoError(t, err)

	assert.Len(t, r.Written, 5)
	assert.Empty(t, r.Skipped)

	assert.Equal(t, "soc2-cc1", readFile(t, filepath.Join(dest, "frameworks/soc2/cc1.yaml")))
	assert.Equal(t, "rego-cc1", readFile(t, filepath.Join(dest, "frameworks/soc2/policies/cc1.rego")))
	assert.Equal(t, "iso42001-r", readFile(t, filepath.Join(dest, "frameworks/iso42001/r.yaml")))
}

func TestFrameworks_FilterByName(t *testing.T) {
	dest := t.TempDir()
	r, err := scaffold.Frameworks(newMockFS(), dest, []string{"soc2"}, false)
	require.NoError(t, err)

	assert.Len(t, r.Written, 3)
	for _, p := range r.Written {
		assert.Contains(t, p, "soc2", "iso42001 should have been filtered out")
	}

	_, err = os.Stat(filepath.Join(dest, "frameworks/iso42001/r.yaml"))
	assert.True(t, os.IsNotExist(err))
}

func TestFrameworks_SkipsExisting(t *testing.T) {
	dest := t.TempDir()
	target := filepath.Join(dest, "frameworks/soc2/cc1.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
	require.NoError(t, os.WriteFile(target, []byte("existing-content"), 0o644))

	r, err := scaffold.Frameworks(newMockFS(), dest, nil, false)
	require.NoError(t, err)

	assert.Contains(t, r.Skipped, target, "should have skipped pre-existing file")
	assert.Equal(t, "existing-content", readFile(t, target), "content should be preserved")
}

func TestFrameworks_ForceOverwrites(t *testing.T) {
	dest := t.TempDir()
	target := filepath.Join(dest, "frameworks/soc2/cc1.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o644))

	r, err := scaffold.Frameworks(newMockFS(), dest, nil, true)
	require.NoError(t, err)

	assert.Contains(t, r.Written, target)
	assert.Equal(t, "soc2-cc1", readFile(t, target))
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

func TestUpgrade_ClassifiesNewModifiedUnchanged(t *testing.T) {
	dest := t.TempDir()

	// Pre-populate: one file matches embed exactly, one differs, one absent.
	require.NoError(t, os.MkdirAll(filepath.Join(dest, "frameworks/soc2/policies"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "frameworks/soc2/cc1.yaml"), []byte("soc2-cc1"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "frameworks/soc2/policies/cc1.rego"), []byte("old-rego"), 0o644))
	// iso42001 files are absent → should be New.

	r, err := scaffold.Upgrade(newMockFS(), dest, nil, false)
	require.NoError(t, err)

	assertContainsSuffix(t, r.Unchanged, "frameworks/soc2/cc1.yaml")
	assertContainsSuffix(t, r.Modified, "frameworks/soc2/policies/cc1.rego")
	assertContainsSuffix(t, r.New, "frameworks/iso42001/r.yaml")

	// Dry-run should NOT have written anything.
	got, err := os.ReadFile(filepath.Join(dest, "frameworks/soc2/policies/cc1.rego"))
	require.NoError(t, err)
	assert.Equal(t, "old-rego", string(got), "dry-run must not modify disk")
}

func TestUpgrade_Apply(t *testing.T) {
	dest := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dest, "frameworks/soc2/policies"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "frameworks/soc2/policies/cc1.rego"), []byte("old-rego"), 0o644))

	_, err := scaffold.Upgrade(newMockFS(), dest, nil, true)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(dest, "frameworks/soc2/policies/cc1.rego"))
	require.NoError(t, err)
	assert.Equal(t, "rego-cc1", string(got), "apply should overwrite with embedded content")

	// New files now exist.
	_, err = os.Stat(filepath.Join(dest, "frameworks/iso42001/r.yaml"))
	require.NoError(t, err)
}

func TestUpgrade_LeavesUserAuthoredFilesAlone(t *testing.T) {
	dest := t.TempDir()
	custom := filepath.Join(dest, "frameworks/internal/custom.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(custom), 0o755))
	require.NoError(t, os.WriteFile(custom, []byte("user-content"), 0o644))

	_, err := scaffold.Upgrade(newMockFS(), dest, nil, true)
	require.NoError(t, err)

	got, err := os.ReadFile(custom)
	require.NoError(t, err)
	assert.Equal(t, "user-content", string(got), "user-authored controls must survive upgrade")
}

func assertContainsSuffix(t *testing.T, paths []string, suffix string) {
	t.Helper()
	for _, p := range paths {
		if filepath.ToSlash(p) == suffix || filepath.ToSlash(p)[len(filepath.ToSlash(p))-len(suffix):] == suffix {
			return
		}
	}
	t.Fatalf("no path ending with %q in %v", suffix, paths)
}

func TestGitHubAction_Writes(t *testing.T) {
	dest := filepath.Join(t.TempDir(), ".github", "workflows", "concord.yml")
	written, err := scaffold.GitHubAction(dest, false)
	require.NoError(t, err)
	assert.True(t, written)
	assert.Contains(t, readFile(t, dest), "concord check")
}
