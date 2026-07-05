package controlpacks_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/pkg/controlpacks"
)

// writePack creates <root>/<fw>/<version>/{pack.yaml,controls/} mirroring the
// on-disk layout `concord controlpack install` extracts.
func writePack(t *testing.T, root, fw, version string) {
	t.Helper()
	dir := filepath.Join(root, fw, version)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "controls"), 0o755))
	manifest := "apiVersion: concord.dev/v1\nkind: ControlPack\nmetadata:\n  id: " + fw + "\n  version: " + version + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, controlpacks.PackFile), []byte(manifest), 0o644))
}

func TestDiscover_FindsNewestVersionPerFramework(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "soc2", "v0.1.0")
	writePack(t, root, "soc2", "v0.2.0") // newer — should win
	writePack(t, root, "iso27001", "v1.0.0")

	packs, err := controlpacks.Discover(root)
	require.NoError(t, err)
	require.Len(t, packs, 2, "one entry per framework")

	byFw := map[string]controlpacks.Discovered{}
	for _, p := range packs {
		byFw[p.Framework] = p
	}
	assert.Equal(t, "v0.2.0", byFw["soc2"].Version, "newest version wins")
	assert.Equal(t, "iso27001", byFw["iso27001"].Framework)

	dirs := controlpacks.ControlsDirs(packs)
	require.Len(t, dirs, 2)
	for _, d := range dirs {
		assert.Equal(t, "controls", filepath.Base(d), "resolves to the pack's controls/ subdir")
	}
}

func TestDiscover_AbsentRootIsNotAnError(t *testing.T) {
	packs, err := controlpacks.Discover(filepath.Join(t.TempDir(), "does-not-exist"))
	require.NoError(t, err)
	assert.Empty(t, packs)
}

func TestControlsDirs_FallsBackToPackRootWhenNoControlsSubdir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "soc2", "v0.1.0")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, controlpacks.PackFile),
		[]byte("apiVersion: concord.dev/v1\nkind: ControlPack\nmetadata:\n  id: soc2\n  version: v0.1.0\n"), 0o644))

	packs, err := controlpacks.Discover(root)
	require.NoError(t, err)
	require.Len(t, packs, 1)
	dirs := controlpacks.ControlsDirs(packs)
	require.Len(t, dirs, 1)
	assert.Equal(t, dir, dirs[0], "no controls/ subdir → walk the pack root")
}
