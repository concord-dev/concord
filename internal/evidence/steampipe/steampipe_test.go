package steampipe

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func newWithRunner(r runner) *Collector {
	c := New(Config{})
	c.runner = r
	return c
}

func TestCollect_ParsesJSONArrayOutput(t *testing.T) {
	payload := `[{"name":"trail-A","is_multi_region_trail":true},{"name":"trail-B","is_multi_region_trail":false}]`
	c := newWithRunner(func(_ context.Context, _ string, args ...string) ([]byte, []byte, error) {
		require.Contains(t, args, "json", "should request JSON output")
		return []byte(payload), nil, nil
	})

	out, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "steampipe",
		Params: map[string]any{
			"query": "SELECT name, is_multi_region_trail FROM aws_cloudtrail_trail",
		},
	})
	require.NoError(t, err)
	got := out.(map[string]any)
	rows := got["rows"].([]map[string]any)
	require.Len(t, rows, 2)
	assert.Equal(t, "trail-A", rows[0]["name"])
	assert.Equal(t, true, rows[0]["is_multi_region_trail"])
	assert.EqualValues(t, 2, got["row_count"])
	assert.NotEmpty(t, got["fetched_at"])
}

func TestCollect_ParsesRowsEnvelope(t *testing.T) {
	payload := `{"rows":[{"id":"x"}]}`
	c := newWithRunner(func(_ context.Context, _ string, _ ...string) ([]byte, []byte, error) {
		return []byte(payload), nil, nil
	})
	out, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "steampipe",
		Params: map[string]any{"query": "select 1"},
	})
	require.NoError(t, err)
	rows := out.(map[string]any)["rows"].([]map[string]any)
	require.Len(t, rows, 1)
	assert.Equal(t, "x", rows[0]["id"])
}

func TestCollect_EmptyResult(t *testing.T) {
	c := newWithRunner(func(_ context.Context, _ string, _ ...string) ([]byte, []byte, error) {
		return []byte(""), nil, nil
	})
	out, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "steampipe",
		Params: map[string]any{"query": "select 1 where false"},
	})
	require.NoError(t, err)
	assert.Empty(t, out.(map[string]any)["rows"])
}

func TestCollect_QueryRequired(t *testing.T) {
	c := newWithRunner(func(context.Context, string, ...string) ([]byte, []byte, error) {
		t.Fatal("should not invoke binary when query is missing")
		return nil, nil, nil
	})
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "steampipe"})
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrUnsupportedType)
}

func TestCollect_BinaryErrorIncludesStderr(t *testing.T) {
	c := newWithRunner(func(context.Context, string, ...string) ([]byte, []byte, error) {
		return nil, []byte("Error: AWS plugin not configured"), errors.New("exit status 1")
	})
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "steampipe",
		Params: map[string]any{"query": "select 1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AWS plugin not configured")
}

func TestCollect_WorkspaceFlagPropagated(t *testing.T) {
	captured := []string{}
	c := newWithRunner(func(_ context.Context, _ string, args ...string) ([]byte, []byte, error) {
		captured = args
		return []byte("[]"), nil, nil
	})
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "steampipe",
		Params: map[string]any{
			"query":     "select 1",
			"workspace": "prod",
		},
	})
	require.NoError(t, err)
	joined := strings.Join(captured, " ")
	assert.Contains(t, joined, "--workspace prod")
}

func TestCollect_ParseRejectsGarbage(t *testing.T) {
	c := newWithRunner(func(context.Context, string, ...string) ([]byte, []byte, error) {
		return []byte("not json at all"), nil, nil
	})
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "steampipe",
		Params: map[string]any{"query": "select 1"},
	})
	require.Error(t, err)
}

func TestProbe_ReturnsVersionString(t *testing.T) {
	c := newWithRunner(func(_ context.Context, _ string, args ...string) ([]byte, []byte, error) {
		require.Equal(t, []string{"--version"}, args)
		return []byte("steampipe v0.23.5\n"), nil, nil
	})
	v, err := c.Probe(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "steampipe v0.23.5", v)
}
