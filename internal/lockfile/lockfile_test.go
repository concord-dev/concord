package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_MissingReturnsEmpty(t *testing.T) {
	lf, err := Load(filepath.Join(t.TempDir(), "missing.lock"))
	require.NoError(t, err)
	assert.Equal(t, "concord.dev/v1", lf.APIVersion)
	assert.Equal(t, "Lock", lf.Kind)
	assert.Empty(t, lf.Plugins)
	assert.Empty(t, lf.ControlPacks)
}

func TestRoundtrip_PluginsAndControlPacks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concord.lock")
	lf := New()
	lf.UpsertPlugin(LockedPlugin{Source: "snyk", Version: "v0.1.0", Digest: "sha256:a"})
	lf.UpsertControlPack(LockedControlPack{Framework: "gdpr", Version: "v0.1.0", Digest: "sha256:b"})

	require.NoError(t, Save(path, lf))
	require.FileExists(t, path)

	got, err := Load(path)
	require.NoError(t, err)
	require.Len(t, got.Plugins, 1)
	require.Len(t, got.ControlPacks, 1)
	assert.Equal(t, "snyk", got.Plugins[0].Source)
	assert.Equal(t, "gdpr", got.ControlPacks[0].Framework)
	assert.NotNil(t, got.UpdatedAt)
}

func TestUpsertPlugin_ReplacesSameSource(t *testing.T) {
	lf := New()
	lf.UpsertPlugin(LockedPlugin{Source: "snyk", Version: "v0.1.0"})
	lf.UpsertPlugin(LockedPlugin{Source: "snyk", Version: "v0.2.0"})
	require.Len(t, lf.Plugins, 1)
	assert.Equal(t, "v0.2.0", lf.Plugins[0].Version)
}

func TestUpsertControlPack_ReplacesSameFramework(t *testing.T) {
	lf := New()
	lf.UpsertControlPack(LockedControlPack{Framework: "gdpr", Version: "v0.1.0"})
	lf.UpsertControlPack(LockedControlPack{Framework: "gdpr", Version: "v0.2.0"})
	require.Len(t, lf.ControlPacks, 1)
	assert.Equal(t, "v0.2.0", lf.ControlPacks[0].Version)
}

func TestSave_StableOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concord.lock")
	lf := New()
	lf.UpsertPlugin(LockedPlugin{Source: "snyk"})
	lf.UpsertPlugin(LockedPlugin{Source: "aws"})
	lf.UpsertControlPack(LockedControlPack{Framework: "soc2"})
	lf.UpsertControlPack(LockedControlPack{Framework: "gdpr"})
	require.NoError(t, Save(path, lf))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	awsIdx := find(raw, []byte("source: aws"))
	snykIdx := find(raw, []byte("source: snyk"))
	gdprIdx := find(raw, []byte("framework: gdpr"))
	soc2Idx := find(raw, []byte("framework: soc2"))
	require.Greater(t, snykIdx, awsIdx, "plugins should be alphabetical")
	require.Greater(t, soc2Idx, gdprIdx, "control packs should be alphabetical")
}

func TestRemoveAndLookup(t *testing.T) {
	lf := New()
	lf.UpsertPlugin(LockedPlugin{Source: "snyk"})
	lf.UpsertControlPack(LockedControlPack{Framework: "gdpr"})

	assert.NotNil(t, lf.LookupPlugin("snyk"))
	assert.NotNil(t, lf.LookupControlPack("gdpr"))
	assert.True(t, lf.RemovePlugin("snyk"))
	assert.True(t, lf.RemoveControlPack("gdpr"))
	assert.False(t, lf.RemovePlugin("snyk"))
	assert.False(t, lf.RemoveControlPack("gdpr"))
	assert.Nil(t, lf.LookupPlugin("snyk"))
	assert.Nil(t, lf.LookupControlPack("gdpr"))
}

func find(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
