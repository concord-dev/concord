package evidence_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/concord-dev/concord/internal/evidence"
)

func TestStringParam_Literal(t *testing.T) {
	got := evidence.StringParam(map[string]any{"repo": "owner/name"}, "repo", "def")
	assert.Equal(t, "owner/name", got)
}

func TestStringParam_Default(t *testing.T) {
	got := evidence.StringParam(nil, "repo", "def")
	assert.Equal(t, "def", got)
}

func TestStringParam_MissingKey(t *testing.T) {
	got := evidence.StringParam(map[string]any{"branch": "main"}, "repo", "def")
	assert.Equal(t, "def", got)
}

func TestStringParam_EnvSubstitution(t *testing.T) {
	t.Setenv("MY_REPO", "alpha/beta")
	got := evidence.StringParam(map[string]any{"repo": "${env.MY_REPO}"}, "repo", "def")
	assert.Equal(t, "alpha/beta", got)
}

func TestStringParam_EnvFallsBackOnEmpty(t *testing.T) {
	t.Setenv("UNSET_VAR", "")
	got := evidence.StringParam(map[string]any{"repo": "${env.UNSET_VAR}"}, "repo", "fallback-default")
	assert.Equal(t, "fallback-default", got)
}

func TestStringParam_PartialEnvSubstitution(t *testing.T) {
	t.Setenv("OWNER", "concord-dev")
	got := evidence.StringParam(map[string]any{"repo": "${env.OWNER}/concord"}, "repo", "def")
	assert.Equal(t, "concord-dev/concord", got)
}

func TestStringParam_NonStringValue(t *testing.T) {
	got := evidence.StringParam(map[string]any{"repo": 42}, "repo", "def")
	assert.Equal(t, "def", got)
}

func TestStringSliceParam_Literal(t *testing.T) {
	got := evidence.StringSliceParam(map[string]any{"paths": []any{"a/*.md", "b/*.go"}}, "paths")
	assert.Equal(t, []string{"a/*.md", "b/*.go"}, got)
}

func TestStringSliceParam_MissingKeyReturnsNil(t *testing.T) {
	got := evidence.StringSliceParam(map[string]any{}, "paths")
	assert.Nil(t, got)
}

func TestStringSliceParam_NonListReturnsNil(t *testing.T) {
	got := evidence.StringSliceParam(map[string]any{"paths": "a/*.md"}, "paths")
	assert.Nil(t, got)
}

func TestStringSliceParam_EnvSubstitutionPerElement(t *testing.T) {
	t.Setenv("BASE", "docs")
	got := evidence.StringSliceParam(map[string]any{
		"paths": []any{"${env.BASE}/ai/*.md", "literal.md"},
	}, "paths")
	assert.Equal(t, []string{"docs/ai/*.md", "literal.md"}, got)
}

func TestStringSliceParam_DropsNonStringElements(t *testing.T) {
	got := evidence.StringSliceParam(map[string]any{
		"paths": []any{"keep.md", 42, "also-keep.md"},
	}, "paths")
	assert.Equal(t, []string{"keep.md", "also-keep.md"}, got)
}
