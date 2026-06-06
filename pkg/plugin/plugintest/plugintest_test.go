package plugintest_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord/pkg/plugin"
	"github.com/concord-dev/concord/pkg/plugin/plugintest"
)

type echoCollector struct{}

func (echoCollector) Source() string                { return "echo" }
func (echoCollector) Version() string               { return "v0" }
func (echoCollector) Probe(_ context.Context) error { return nil }
func (echoCollector) Handlers() []plugin.TypeHandler {
	return []plugin.TypeHandler{{
		Type: "echo",
		Handle: func(_ context.Context, ref plugin.EvidenceRef) (any, error) {
			if ref.ID == "boom" {
				return nil, errors.New("boom")
			}
			return map[string]any{"echo": ref.Params["msg"]}, nil
		},
	}}
}

func TestRun_PassesAndFailsCorrectly(t *testing.T) {
	cases := []plugintest.Case{
		{
			Name: "ok",
			Ref:  plugin.EvidenceRef{Type: "echo", Params: map[string]any{"msg": "hi"}},
			Expected: map[string]any{"echo": "hi"},
		},
		{
			Name:        "explicit-error",
			Ref:         plugin.EvidenceRef{Type: "echo", ID: "boom"},
			ExpectError: true,
		},
		{
			Name:          "unsupported-type",
			Ref:           plugin.EvidenceRef{Type: "other"},
			ExpectErrorIs: plugin.ErrUnsupportedType,
		},
	}
	plugintest.Run(t, echoCollector{}, cases)
}

func TestFixturesDir_LoadsInputAndExpected(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "case1.json"),
		[]byte(`{"msg": "hello"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "case1.expected.json"),
		[]byte(`{"echo": "hello"}`), 0o644))

	cases := plugintest.FixturesDir(t, dir, plugin.EvidenceRef{Type: "echo"})
	require.Len(t, cases, 1)
	require.Equal(t, "case1", cases[0].Name)
	require.Equal(t, "echo", cases[0].Ref.Type)
	require.Equal(t, "hello", cases[0].Ref.Params["msg"])

	var expected map[string]any
	raw, _ := json.Marshal(cases[0].Expected)
	require.NoError(t, json.Unmarshal(raw, &expected))
	require.Equal(t, "hello", expected["echo"])
}

func TestProbe_HonoursEnvOverrides(t *testing.T) {
	t.Setenv("CONCORD_PROBE_HOST", "old")
	plugintest.Probe(t, echoCollector{}, map[string]string{"CONCORD_PROBE_HOST": "scoped"})
	require.Equal(t, "old", os.Getenv("CONCORD_PROBE_HOST"), "env must be restored after Probe")
}
