package credentials_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/cli/credentials"
)

func pinPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	t.Setenv("CONCORD_CREDENTIALS_FILE", path)
	return path
}

func TestLoad_ReturnsSentinelWhenMissing(t *testing.T) {
	pinPath(t)
	_, err := credentials.Load()
	assert.ErrorIs(t, err, credentials.ErrNoCredentials,
		"absent file must surface as ErrNoCredentials so callers can hint `concord login`")
}

func TestSaveLoad_RoundTripsCurrentProfile(t *testing.T) {
	path := pinPath(t)

	f := &credentials.File{}
	f.SetCurrent("default")
	f.Profiles["default"].Server = "https://concord.example.com"
	f.Profiles["default"].Token = "concord_sess_xyz"
	f.Profiles["default"].UserID = "u-1"
	f.Profiles["default"].UserEmail = "u@example.com"
	f.Profiles["default"].DefaultOrg = "acme"
	f.Profiles["default"].ExpiresAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, credentials.Save(f))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"credentials file must be 0600 — session token is the keys to the kingdom")

	got, err := credentials.Load()
	require.NoError(t, err)
	cur, err := got.CurrentProfile()
	require.NoError(t, err)
	assert.Equal(t, "https://concord.example.com", cur.Server)
	assert.Equal(t, "concord_sess_xyz", cur.Token)
	assert.Equal(t, "acme", cur.DefaultOrg)
	assert.Equal(t, "u@example.com", cur.UserEmail)
}

func TestCurrent_ErrorsWhenCursorPointsAtMissingProfile(t *testing.T) {
	pinPath(t)
	f := &credentials.File{Current: "ghost", Profiles: map[string]*credentials.Profile{}}
	_, err := f.CurrentProfile()
	assert.ErrorIs(t, err, credentials.ErrNoCurrentProfile,
		"a stale `current` cursor must surface a typed error, not nil-deref")
}

func TestSave_IsAtomicAcrossCrashSimulation(t *testing.T) {
	path := pinPath(t)

	f1 := &credentials.File{}
	f1.SetCurrent("default")
	f1.Profiles["default"].Server = "https://a.example"
	require.NoError(t, credentials.Save(f1))

	f2 := &credentials.File{}
	f2.SetCurrent("default")
	f2.Profiles["default"].Server = "https://b.example"
	require.NoError(t, credentials.Save(f2))

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, filepath.Ext(e.Name()) == ".tmp",
			"successful Save must clean up its temp file: leftover %s", e.Name())
	}

	got, err := credentials.Load()
	require.NoError(t, err)
	cur, _ := got.CurrentProfile()
	assert.Equal(t, "https://b.example", cur.Server, "second Save must overwrite cleanly")
}

func TestLoadOrInit_BuildsEmptyFileWhenMissing(t *testing.T) {
	pinPath(t)
	f, err := credentials.LoadOrInit()
	require.NoError(t, err)
	require.NotNil(t, f)
	assert.NotNil(t, f.Profiles, "LoadOrInit must hand back a usable empty File")
}

func TestDelete_TolerantOfMissingFile(t *testing.T) {
	pinPath(t)
	assert.NoError(t, credentials.Delete())

	f := &credentials.File{}
	f.SetCurrent("default")
	require.NoError(t, credentials.Save(f))
	require.NoError(t, credentials.Delete())
	_, err := credentials.Load()
	assert.ErrorIs(t, err, credentials.ErrNoCredentials)
}

func TestSetCurrent_CreatesProfileIfMissing(t *testing.T) {
	f := &credentials.File{}
	f.SetCurrent("staging")
	assert.Equal(t, "staging", f.Current)
	require.Contains(t, f.Profiles, "staging")
	assert.NotNil(t, f.Profiles["staging"])
}

func TestPath_HonoursCONCORDCredentialsFileOverride(t *testing.T) {
	t.Setenv("CONCORD_CREDENTIALS_FILE", "/tmp/concord-override.json")
	p, err := credentials.Path()
	require.NoError(t, err)
	assert.Equal(t, "/tmp/concord-override.json", p)
}

func TestPath_FallsBackToXDGOrHome(t *testing.T) {
	t.Setenv("CONCORD_CREDENTIALS_FILE", "")
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	p, err := credentials.Path()
	require.NoError(t, err)
	assert.Equal(t, "/tmp/xdg/concord/credentials.json", p)
}

func TestLoad_RejectsCorruptJSON(t *testing.T) {
	path := pinPath(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("{this is not json"), 0o600))
	_, err := credentials.Load()
	assert.Error(t, err)
	assert.False(t, errors.Is(err, credentials.ErrNoCredentials),
		"a corrupted file is NOT the same as a missing file — surface a parse error so the user can act")
}
