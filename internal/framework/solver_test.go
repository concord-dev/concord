package framework

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterMatching_PicksHighest(t *testing.T) {
	tags := []string{"v0.1.0", "v0.1.1", "v0.2.0", "v1.0.0", "v1.0.0-rc1", "not-semver"}
	cs, err := parseConstraints([]string{"^v0.1.0"})
	require.NoError(t, err)
	matching := filterMatching(tags, cs)
	require.Len(t, matching, 2)
	sort.Sort(byVersionDesc(matching))
	assert.Equal(t, "v0.1.1", tagString(matching[0]))
	assert.Equal(t, "v0.1.0", tagString(matching[1]))
}

func TestFilterMatching_IntersectsRanges(t *testing.T) {
	tags := []string{"v0.0.9", "v0.1.0", "v0.1.5", "v0.2.0", "v0.3.0"}
	cs, err := parseConstraints([]string{">=v0.1.0", "<v0.3.0"})
	require.NoError(t, err)
	matching := filterMatching(tags, cs)
	require.Len(t, matching, 3)
}

func TestFilterMatching_NoMatch(t *testing.T) {
	tags := []string{"v0.1.0", "v0.2.0"}
	cs, err := parseConstraints([]string{"^v1.0.0"})
	require.NoError(t, err)
	matching := filterMatching(tags, cs)
	assert.Empty(t, matching)
}

func TestParseConstraints_StripsLeadingV(t *testing.T) {
	cs, err := parseConstraints([]string{"^v0.1.0"})
	require.NoError(t, err)
	require.Len(t, cs, 1)
	assert.Contains(t, cs[0].String(), "0.1.0")
}

func TestAllEqual(t *testing.T) {
	v, ok := allEqual([]string{"=v1.0.0", "=v1.0.0"})
	assert.True(t, ok)
	assert.Equal(t, "v1.0.0", v)

	_, ok = allEqual([]string{"^v0.1.0"})
	assert.False(t, ok)

	_, ok = allEqual([]string{"=v1.0.0", "=v2.0.0"})
	assert.False(t, ok)
}

func TestConcreteVersion(t *testing.T) {
	assert.Equal(t, "v0.1.0", concreteVersion([]string{"^v0.1", "=v0.1.0"}))
	assert.Equal(t, "", concreteVersion([]string{"^v0.1"}))
}

func TestPluginOCIRefFor(t *testing.T) {
	assert.Equal(t, "ghcr.io/concord-dev/concord-plugin-snyk", pluginOCIRefFor("snyk"))
	assert.Equal(t, "ghcr.io/other/x", pluginOCIRefFor("ghcr.io/other/x"))
}

func TestDedup(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, dedup([]string{"b", "a", "b", "a"}))
}
