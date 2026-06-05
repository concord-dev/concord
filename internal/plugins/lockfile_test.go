package plugins

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadLockfile_MissingReturnsEmpty(t *testing.T) {
	lf, err := LoadLockfile(filepath.Join(t.TempDir(), "missing.lock"))
	require.NoError(t, err)
	assert.Equal(t, "concord.dev/v1", lf.APIVersion)
	assert.Equal(t, "Lock", lf.Kind)
	assert.Empty(t, lf.Plugins)
}

func TestSaveAndLoadLockfile_Roundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concord.lock")
	lf := NewLockfile()
	lf.Upsert(LockedPlugin{
		Source:   "snyk",
		Artifact: "ghcr.io/concord-dev/concord-plugin-snyk",
		Version:  "v0.1.0",
		Digest:   "sha256:abc",
		Signer:   "https://github.com/concord-dev/concord-plugin-snyk/.github/workflows/release.yml@refs/tags/v0.1.0",
		Platform: "linux/amd64",
	})

	require.NoError(t, SaveLockfile(path, lf))
	require.FileExists(t, path)

	got, err := LoadLockfile(path)
	require.NoError(t, err)
	require.Len(t, got.Plugins, 1)
	assert.Equal(t, "snyk", got.Plugins[0].Source)
	assert.Equal(t, "sha256:abc", got.Plugins[0].Digest)
	assert.NotNil(t, got.UpdatedAt)
}

func TestUpsert_ReplacesSameSource(t *testing.T) {
	lf := NewLockfile()
	lf.Upsert(LockedPlugin{Source: "snyk", Version: "v0.1.0", Digest: "sha256:a"})
	lf.Upsert(LockedPlugin{Source: "snyk", Version: "v0.2.0", Digest: "sha256:b"})
	require.Len(t, lf.Plugins, 1)
	assert.Equal(t, "v0.2.0", lf.Plugins[0].Version)
}

func TestSaveLockfile_StableSourceOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concord.lock")
	lf := NewLockfile()
	lf.Upsert(LockedPlugin{Source: "snyk", Version: "v1"})
	lf.Upsert(LockedPlugin{Source: "aws", Version: "v1"})
	lf.Upsert(LockedPlugin{Source: "hello", Version: "v1"})
	require.NoError(t, SaveLockfile(path, lf))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	awsIdx := find(raw, []byte("aws"))
	helloIdx := find(raw, []byte("hello"))
	snykIdx := find(raw, []byte("snyk"))
	require.True(t, awsIdx < helloIdx && helloIdx < snykIdx, "sources should be alphabetically sorted in the file")
}

func TestRemove(t *testing.T) {
	lf := NewLockfile()
	lf.Upsert(LockedPlugin{Source: "snyk", Version: "v0.1.0"})
	lf.Upsert(LockedPlugin{Source: "aws", Version: "v0.1.0"})
	assert.True(t, lf.Remove("snyk"))
	assert.False(t, lf.Remove("snyk"))
	require.Len(t, lf.Plugins, 1)
	assert.Equal(t, "aws", lf.Plugins[0].Source)
}

func TestLookup(t *testing.T) {
	lf := NewLockfile()
	lf.Upsert(LockedPlugin{Source: "snyk", Version: "v0.1.0"})
	assert.NotNil(t, lf.Lookup("snyk"))
	assert.Nil(t, lf.Lookup("missing"))
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
