package policy

import (
	"context"
	"testing"
	"time"

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

// freshnessRule denies when the reviewed_at timestamp is more than 90 days
// before time.now_ns() — the shape every freshness control in the packs uses.
const freshnessRule = `package concord.freshness

import rego.v1

deny contains msg if {
    reviewed := time.parse_rfc3339_ns(input.reviewed_at)
    cutoff := time.now_ns() - (90 * 86400000000000)
    reviewed < cutoff
    msg := "review is stale"
}
`

// TestEvaluateWithModulesAt_PinnedClock proves the clock pin: the same fixture
// (reviewed_at fixed) passes when evaluated as-of a time within the window and
// fails when evaluated as-of a time past it. This is what stops static
// freshness fixtures from rotting during lint as real wall-clock time advances.
func TestEvaluateWithModulesAt_PinnedClock(t *testing.T) {
	e := New()
	mods := map[string]string{"policy.rego": freshnessRule}
	input := map[string]any{"reviewed_at": "2026-04-15T00:00:00Z"}

	// As-of 30 days later: within the 90-day window → passes.
	withinWindow, err := e.EvaluateWithModulesAt(context.Background(), mods, "concord.freshness", input, time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.True(t, withinWindow.Pass, "review 30 days old should pass")

	// As-of 200 days later: past the window → fails. Without the pin this same
	// fixture would flip from pass to fail purely as wall-clock time advanced.
	pastWindow, err := e.EvaluateWithModulesAt(context.Background(), mods, "concord.freshness", input, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.False(t, pastWindow.Pass, "review 200 days old should fail")
}

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
