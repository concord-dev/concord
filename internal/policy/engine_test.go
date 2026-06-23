package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const denyRule = `package concord.test

import rego.v1

deny contains msg if {
    not input.protected
    msg := "branch is not protected"
}

deny contains msg if {
    count := input.reviewers
    count < 1
    msg := sprintf("only %d reviewers required", [count])
}

warn contains msg if {
    not input.code_owner
    msg := "no CODEOWNERS required"
}
`

func TestEvaluateSource_Deny(t *testing.T) {
	e := New()
	res, err := e.EvaluateSource(context.Background(), denyRule, "concord.test", map[string]any{
		"protected":  false,
		"reviewers":  0,
		"code_owner": false,
	})
	require.NoError(t, err)
	assert.False(t, res.Pass)
	assert.ElementsMatch(t, []string{
		"branch is not protected",
		"only 0 reviewers required",
	}, res.Deny)
	assert.ElementsMatch(t, []string{"no CODEOWNERS required"}, res.Warn)
}

func TestEvaluateSource_Pass(t *testing.T) {
	e := New()
	res, err := e.EvaluateSource(context.Background(), denyRule, "concord.test", map[string]any{
		"protected":  true,
		"reviewers":  2,
		"code_owner": true,
	})
	require.NoError(t, err)
	assert.True(t, res.Pass)
	assert.Empty(t, res.Deny)
	assert.Empty(t, res.Warn)
}

func TestEvaluateSource_InvalidRego(t *testing.T) {
	e := New()
	_, err := e.EvaluateSource(context.Background(), "this is not rego", "concord.test", nil)
	require.Error(t, err)
}
