package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/pkg/config"
)

func TestLoad_MissingFileReturnsEmpty(t *testing.T) {
	c, err := config.Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Empty(t, c.Controls.Params)
}

func TestLoad_ParsesParams(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "concord.yaml")
	require.NoError(t, os.WriteFile(p, []byte(`apiVersion: concord.dev/v1
kind: Config
metadata:
  name: test-repo
controls:
  path: ./controls
  params:
    SOC2-CC8.1:
      min_reviewers: 2
    ISO42001-6.1:
      max_age_days: 90
`), 0o644))

	c, err := config.Load(p)
	require.NoError(t, err)
	assert.Equal(t, "test-repo", c.Metadata.Name)
	assert.Equal(t, "./controls", c.Controls.Path)
	require.NotNil(t, c.Controls.Params)
	assert.EqualValues(t, 2, c.Controls.Params["SOC2-CC8.1"]["min_reviewers"])
	assert.EqualValues(t, 90, c.Controls.Params["ISO42001-6.1"]["max_age_days"])
}

func TestLoad_MalformedYAMLErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "concord.yaml")
	require.NoError(t, os.WriteFile(p, []byte("not: valid: yaml: ::"), 0o644))

	_, err := config.Load(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing")
}
