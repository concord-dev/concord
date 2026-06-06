package plugin_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord/pkg/plugin"
)

type fakeCollector struct {
	source, version string
	probeErr        error
	handlers        []plugin.TypeHandler
}

func (f *fakeCollector) Source() string                       { return f.source }
func (f *fakeCollector) Version() string                      { return f.version }
func (f *fakeCollector) Probe(_ context.Context) error        { return f.probeErr }
func (f *fakeCollector) Handlers() []plugin.TypeHandler       { return f.handlers }

func TestSimpleAdapter_RoutesByType(t *testing.T) {
	c := &fakeCollector{
		source: "fake", version: "v0.0.1",
		handlers: []plugin.TypeHandler{
			{Type: "alpha", Handle: func(_ context.Context, ref plugin.EvidenceRef) (any, error) {
				return map[string]any{"hit": "alpha", "id": ref.ID}, nil
			}},
			{Type: "beta", Handle: func(_ context.Context, _ plugin.EvidenceRef) (any, error) {
				return "beta-payload", nil
			}},
		},
	}
	a := plugin.NewSimpleAdapter(c)

	out, err := a.Collect(context.Background(), plugin.EvidenceRef{Type: "alpha", ID: "e1"})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"hit": "alpha", "id": "e1"}, out)

	out, err = a.Collect(context.Background(), plugin.EvidenceRef{Type: "beta"})
	require.NoError(t, err)
	assert.Equal(t, "beta-payload", out)

	_, err = a.Collect(context.Background(), plugin.EvidenceRef{Type: "gamma"})
	assert.ErrorIs(t, err, plugin.ErrUnsupportedType)
}

func TestSimpleAdapter_CapabilitiesReflectImpl(t *testing.T) {
	c := &fakeCollector{
		source: "fake", version: "v0.0.2",
		handlers: []plugin.TypeHandler{
			{Type: "beta"}, {Type: "alpha"},
		},
	}
	a := plugin.NewSimpleAdapter(c,
		plugin.WithDocs("https://example.com"),
		plugin.WithRequiredEnv("FAKE_TOKEN"),
		plugin.WithOptionalEnv("FAKE_REGION"),
	)
	caps := a.Capabilities()
	assert.Equal(t, "fake", caps.Source)
	assert.Equal(t, "v0.0.2", caps.Version)
	assert.Equal(t, []string{"alpha", "beta"}, caps.SupportedTypes, "types sorted alphabetically")
	assert.Equal(t, []string{"FAKE_TOKEN"}, caps.RequiredEnv)
	assert.Equal(t, "https://example.com", caps.DocsURL)
}

func TestSimpleAdapter_ProbeFailsOnMissingRequiredEnv(t *testing.T) {
	_ = os.Unsetenv("FAKE_TOKEN_X")
	c := &fakeCollector{source: "fake", version: "v0.0.1"}
	a := plugin.NewSimpleAdapter(c, plugin.WithRequiredEnv("FAKE_TOKEN_X"))
	_, err := a.Probe(context.Background())
	require.Error(t, err)
}

func TestSimpleAdapter_PropagatesImplProbeError(t *testing.T) {
	c := &fakeCollector{source: "fake", version: "v", probeErr: errors.New("nope")}
	a := plugin.NewSimpleAdapter(c)
	_, err := a.Probe(context.Background())
	require.Error(t, err)
}
