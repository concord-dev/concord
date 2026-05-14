package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubProber struct {
	info string
	err  error
}

func (s stubProber) Probe(ctx context.Context) (string, error) { return s.info, s.err }

func TestDoctor_PassesAllSections(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "concord.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`apiVersion: concord.dev/v1
kind: Concord
metadata:
  name: TestCo
`), 0o644))

	d := &doctor{w: &bytes.Buffer{}, ctx: context.Background()}
	d.runConfig(cfgPath)
	d.runControls("../../controls")
	d.probe("github", stubProber{info: "authenticated as octocat"}, "")

	assert.GreaterOrEqual(t, d.passed, 3, "config + controls + github should all pass")
	assert.Equal(t, 0, d.failed)
}

func TestDoctor_MissingConfigWarnsButDoesNotFail(t *testing.T) {
	d := &doctor{w: &bytes.Buffer{}, ctx: context.Background()}
	d.runConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	assert.Equal(t, 0, d.failed)
	assert.Equal(t, 1, d.warned)
}

func TestDoctor_MissingControlsFails(t *testing.T) {
	d := &doctor{w: &bytes.Buffer{}, ctx: context.Background()}
	d.runControls(filepath.Join(t.TempDir(), "no-controls"))
	assert.Equal(t, 1, d.failed)
}

func TestDoctor_EmptyControlsDirWarns(t *testing.T) {
	dir := t.TempDir()
	d := &doctor{w: &bytes.Buffer{}, ctx: context.Background()}
	d.runControls(dir)
	assert.Equal(t, 0, d.failed)
	assert.Equal(t, 1, d.warned)
}

func TestDoctor_ProbeFailureSurfacesAsFail(t *testing.T) {
	d := &doctor{w: &bytes.Buffer{}, ctx: context.Background()}
	d.probe("github", stubProber{err: errors.New("github /user returned 401")}, "set CONCORD_GITHUB_TOKEN")

	assert.Equal(t, 1, d.failed)
	assert.Equal(t, 0, d.passed)
	out := d.w.(*bytes.Buffer).String()
	assert.Contains(t, out, "401")
	assert.Contains(t, out, "CONCORD_GITHUB_TOKEN", "hint should be shown so user can fix it")
}

func TestDoctor_SummaryReflectsCounts(t *testing.T) {
	buf := &bytes.Buffer{}
	d := &doctor{w: buf, ctx: context.Background()}
	d.pass("a", "")
	d.warn("b", "")
	d.fail("c", "boom")
	d.printSummary()

	out := buf.String()
	assert.Contains(t, out, "Summary")
	assert.Contains(t, out, "doctor found 1 blocking issue")
}

func TestSummarizeFrameworks_StableOrdering(t *testing.T) {
	in := map[string]int{"soc2": 12, "iso42001": 3, "cis-aws": 5}
	got := summarizeFrameworks(in)
	assert.Equal(t, "cis-aws=5, iso42001=3, soc2=12", got, "must be alphabetical")
}
