package runner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/policy"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const cc81Path = "controls/frameworks/soc2/cc8.1-change-management.yaml"

func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../..")
	require.NoError(t, err)
	return abs
}

func TestRunCC8_1Pass(t *testing.T) {
	f := runFixture(t, "cc8.1-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
	assert.Empty(t, f.Messages)
}

func TestRunCC8_1NoProtection(t *testing.T) {
	f := runFixture(t, "cc8.1-no-protection.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `default branch "main" is not protected`)
	assert.Len(t, f.Messages, 1, "expected exactly one deny for unprotected branch; got %v", f.Messages)
}

func TestRunCC8_1NoReviews(t *testing.T) {
	f := runFixture(t, "cc8.1-no-reviews.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "default branch requires 0 approving reviews; minimum is 1")
}

func TestRunCC8_1ForcePushAndAdminBypass(t *testing.T) {
	f := runFixture(t, "cc8.1-force-push.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "default branch allows force pushes")
	assert.Contains(t, f.Messages, "default branch allows deletions")
	assert.Contains(t, f.Messages, "branch protection does not apply to administrators (enforce_admins is off)")
}

func TestRunCC8_1ParamOverride_StricterReviewerCount(t *testing.T) {
	controlPath := filepath.Join(repoRoot(t), cc81Path)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)
	c.Spec.Evidence[0].Fixture = "./tests/fixtures/cc8.1-pass.json"

	// The pass fixture has required_approving_review_count = 2.
	// With default min_reviewers = 1, this passes. With override min_reviewers = 3, it must fail.
	r := New(policy.New(), evidence.NewFileCollector()).SetParams(map[string]map[string]any{
		"SOC2-CC8.1": {"min_reviewers": 3},
	})
	f := r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})

	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "default branch requires 2 approving reviews; minimum is 3")
}

func TestRunCC8_1ParamOverride_DefaultStillWorks(t *testing.T) {
	controlPath := filepath.Join(repoRoot(t), cc81Path)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)
	c.Spec.Evidence[0].Fixture = "./tests/fixtures/cc8.1-pass.json"

	// No params installed → default of 1 applies → fixture (which has 2 reviewers) passes.
	r := New(policy.New(), evidence.NewFileCollector())
	f := r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v", f.Messages)
}

func runFixture(t *testing.T, fixture string) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), cc81Path)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)

	c.Spec.Evidence[0].Fixture = "./tests/fixtures/" + fixture

	r := New(policy.New(), evidence.NewFileCollector())
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
}
