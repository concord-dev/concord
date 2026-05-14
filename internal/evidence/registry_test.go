package evidence_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type stubCollector struct {
	value any
	err   error
}

func (s *stubCollector) Collect(_ evidence.Context, _ apiv1.EvidenceRef) (any, error) {
	return s.value, s.err
}

func TestRegistry_DispatchesBySource(t *testing.T) {
	r := evidence.NewRegistry()
	r.Register("github", &stubCollector{value: "from-github"})

	v, err := r.Collect(evidence.Context{}, apiv1.EvidenceRef{
		ID: "x", Source: "github",
	})
	require.NoError(t, err)
	assert.Equal(t, "from-github", v)
}

func TestRegistry_FallsBackToFixtureWhenNoCollector(t *testing.T) {
	dir := t.TempDir()
	fixturePath := filepath.Join(dir, "x.json")
	require.NoError(t, os.WriteFile(fixturePath, []byte(`{"k":"v"}`), 0o644))

	r := evidence.NewRegistry()
	v, err := r.Collect(evidence.Context{ControlDir: dir}, apiv1.EvidenceRef{
		ID: "x", Source: "github", Fixture: "./x.json",
	})
	require.NoError(t, err)

	m, ok := v.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "v", m["k"])
}

func TestRegistry_ErrorsWhenNoCollectorAndNoFixture(t *testing.T) {
	r := evidence.NewRegistry()
	_, err := r.Collect(evidence.Context{}, apiv1.EvidenceRef{
		ID: "x", Source: "github",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no collector registered")
}

func TestRegistry_PropagatesCollectorError(t *testing.T) {
	r := evidence.NewRegistry()
	r.Register("github", &stubCollector{err: errors.New("api down")})

	_, err := r.Collect(evidence.Context{}, apiv1.EvidenceRef{
		ID: "x", Source: "github", Fixture: "./would-fall-back.json",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api down")
}

func TestRegistry_FixturesOnlyBypassesRegisteredCollector(t *testing.T) {
	dir := t.TempDir()
	fixturePath := filepath.Join(dir, "x.json")
	require.NoError(t, os.WriteFile(fixturePath, []byte(`"hello"`), 0o644))

	r := evidence.NewRegistry()
	r.Register("github", &stubCollector{err: errors.New("should not be called")})
	r.SetFixturesOnly(true)

	v, err := r.Collect(evidence.Context{ControlDir: dir}, apiv1.EvidenceRef{
		Source: "github", Fixture: "./x.json",
	})
	require.NoError(t, err)
	assert.Equal(t, "hello", v)
}

func TestRegistry_FallsBackOnUnsupportedType(t *testing.T) {
	dir := t.TempDir()
	fixturePath := filepath.Join(dir, "x.json")
	require.NoError(t, os.WriteFile(fixturePath, []byte(`"from-fixture"`), 0o644))

	r := evidence.NewRegistry()
	r.Register("github", &stubCollector{err: evidence.ErrUnsupportedType})

	v, err := r.Collect(evidence.Context{ControlDir: dir}, apiv1.EvidenceRef{
		Source: "github", Fixture: "./x.json",
	})
	require.NoError(t, err)
	assert.Equal(t, "from-fixture", v)
}

func TestRegistry_ErrorsOnUnsupportedTypeWithoutFixture(t *testing.T) {
	r := evidence.NewRegistry()
	r.Register("github", &stubCollector{err: evidence.ErrUnsupportedType})

	_, err := r.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github",
	})
	require.Error(t, err)
}

func TestRegistry_FileSourceUsesFileCollector(t *testing.T) {
	dir := t.TempDir()
	fixturePath := filepath.Join(dir, "x.json")
	require.NoError(t, os.WriteFile(fixturePath, []byte(`42`), 0o644))

	r := evidence.NewRegistry()
	v, err := r.Collect(evidence.Context{ControlDir: dir}, apiv1.EvidenceRef{
		Source: "file", Fixture: "./x.json",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 42, v)
}
