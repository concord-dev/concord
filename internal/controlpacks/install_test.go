package controlpacks

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePack_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`apiVersion: concord.dev/v1
kind: ControlPack
metadata:
  id: gdpr
  version: v0.1.0
spec:
  controls: [art-5]
  evidence_sources:
    - source: prowler
      version: ">=v1.0.0,<v2.0.0"
`), 0o644))

	p, err := ParsePack(path)
	require.NoError(t, err)
	assert.Equal(t, "gdpr", p.Metadata.ID)
	assert.Equal(t, "v0.1.0", p.Metadata.Version)
	assert.Equal(t, []string{"prowler"}, p.EvidenceSourceNames())
}

func TestParsePack_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pack.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`apiVersion: concord.dev/v1
kind: ControlPack
metadata:
  version: v0.1.0
`), 0o644))

	_, err := ParsePack(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata.id is required")
}

func TestExtractTarGz_HappyPath(t *testing.T) {
	dir := t.TempDir()
	tgz := buildTarGz(t, map[string][]byte{
		"pack.yaml":          []byte("apiVersion: concord.dev/v1\nkind: ControlPack\nmetadata:\n  id: gdpr\n  version: v0.1.0\n"),
		"controls/c1.yaml":   []byte("control1"),
		"policies/c1.rego":   []byte("package c1"),
	})
	require.NoError(t, extractTarGz(bytes.NewReader(tgz), dir))
	for _, p := range []string{"pack.yaml", "controls/c1.yaml", "policies/c1.rego"} {
		_, err := os.Stat(filepath.Join(dir, p))
		require.NoError(t, err, "expected %s after extraction", p)
	}
}

func TestExtractTarGz_RejectsPathTraversal(t *testing.T) {
	tgz := buildTarGz(t, map[string][]byte{
		"../etc/passwd": []byte("escape"),
	})
	err := extractTarGz(bytes.NewReader(tgz), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "escapes install dir")
}

func TestExtractTarGz_RejectsAbsolutePath(t *testing.T) {
	tgz := buildTarGzWithHeader(t, &tar.Header{
		Name:     "/etc/evil",
		Typeflag: tar.TypeReg,
		Size:     int64(len("x")),
		Mode:     0o644,
	}, []byte("x"))
	err := extractTarGz(bytes.NewReader(tgz), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute paths not allowed")
}

func TestExtractTarGz_RejectsSymlinks(t *testing.T) {
	tgz := buildTarGzWithHeader(t, &tar.Header{
		Name:     "link",
		Linkname: "/etc/passwd",
		Typeflag: tar.TypeSymlink,
	}, nil)
	err := extractTarGz(bytes.NewReader(tgz), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlinks not allowed")
}

func TestDefaultFrameworkFromArtifact(t *testing.T) {
	assert.Equal(t, "gdpr", defaultFrameworkFromArtifact("ghcr.io/concord-dev/concord-controlpack-gdpr"))
	assert.Equal(t, "", defaultFrameworkFromArtifact("ghcr.io/concord-dev/something-else"))
}

func buildTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Size:     int64(len(content)),
			Mode:     0o644,
		}))
		_, err := tw.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

func buildTarGzWithHeader(t *testing.T, hdr *tar.Header, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(hdr))
	if len(content) > 0 {
		_, err := tw.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}
