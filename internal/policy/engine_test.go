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

const perResourceRule = `package concord.test

import rego.v1

resource_findings contains v if {
    some u in input.users
    not u.ok
    v := {"resource": u.id, "status": "fail", "messages": [sprintf("%s failed", [u.id])]}
}

resource_findings contains v if {
    some u in input.users
    u.ok
    v := {"resource": u.id, "status": "pass", "messages": []}
}
`

// A policy that defines resource_findings must surface decoded, resource-sorted
// verdicts on Result.Resources; a policy without it leaves Resources empty.
func TestEvaluateSource_ResourceFindings(t *testing.T) {
	e := New()
	res, err := e.EvaluateSource(context.Background(), perResourceRule, "concord.test", map[string]any{
		"users": []any{
			map[string]any{"id": "bucket-b", "ok": false},
			map[string]any{"id": "bucket-a", "ok": true},
		},
	})
	require.NoError(t, err)
	require.Len(t, res.Resources, 2)
	assert.Equal(t, "bucket-a", res.Resources[0].Resource, "verdicts are sorted by resource")
	assert.Equal(t, "pass", res.Resources[0].Status)
	assert.Equal(t, "bucket-b", res.Resources[1].Resource)
	assert.Equal(t, "fail", res.Resources[1].Status)
	assert.Equal(t, []string{"bucket-b failed"}, res.Resources[1].Messages)

	// A control-level policy leaves Resources empty (backward compatible).
	ctrl, err := e.EvaluateSource(context.Background(), denyRule, "concord.test", map[string]any{"protected": true, "reviewers": 2, "code_owner": true})
	require.NoError(t, err)
	assert.Empty(t, ctrl.Resources)
}

func TestEvaluateSource_InvalidRego(t *testing.T) {
	e := New()
	_, err := e.EvaluateSource(context.Background(), "this is not rego", "concord.test", nil)
	require.Error(t, err)
}
