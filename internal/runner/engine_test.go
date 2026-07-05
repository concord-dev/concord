package runner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/policy"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
	"github.com/concord-dev/concord/pkg/controls"
)

const testControlPath = "testdata/change-management.yaml"

func loadTestControl(t *testing.T) controls.Loaded {
	t.Helper()
	c, err := controls.LoadFile(testControlPath)
	require.NoError(t, err)
	return controls.Loaded{Control: c, Path: testControlPath}
}

func TestEngine_Pass(t *testing.T) {
	f := New(policy.New(), evidence.NewFileCollector()).Run(context.Background(), loadTestControl(t))
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
	assert.Empty(t, f.Messages)
}

func TestEngine_FailWithDenyMessage(t *testing.T) {
	l := loadTestControl(t)
	l.Control.Spec.Evidence[0].Fixture = "./tests/fixtures/cc8.1-no-protection.json"
	f := New(policy.New(), evidence.NewFileCollector()).Run(context.Background(), l)
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `default branch "main" is not protected`)
}

// The runner must commit each finding to a digest of the evidence it evaluated,
// and that digest must change when the evidence changes (the P1 trust seam).
func TestEngine_SetsEvidenceFingerprint(t *testing.T) {
	pass := New(policy.New(), evidence.NewFileCollector()).Run(context.Background(), loadTestControl(t))
	assert.NotEmpty(t, pass.EvidenceFingerprint, "a finding with evidence must carry a fingerprint")

	l := loadTestControl(t)
	l.Control.Spec.Evidence[0].Fixture = "./tests/fixtures/cc8.1-no-protection.json"
	fail := New(policy.New(), evidence.NewFileCollector()).Run(context.Background(), l)
	assert.NotEmpty(t, fail.EvidenceFingerprint)
	assert.NotEqual(t, pass.EvidenceFingerprint, fail.EvidenceFingerprint,
		"different evidence must produce a different fingerprint")

	// Deterministic: re-evaluating identical evidence yields the same digest.
	again := New(policy.New(), evidence.NewFileCollector()).Run(context.Background(), loadTestControl(t))
	assert.Equal(t, pass.EvidenceFingerprint, again.EvidenceFingerprint)
}

func TestEngine_ParamOverride(t *testing.T) {
	r := New(policy.New(), evidence.NewFileCollector()).SetParams(map[string]map[string]any{
		"SOC2-CC8.1": {"min_reviewers": 3},
	})
	f := r.Run(context.Background(), loadTestControl(t))
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "default branch requires 2 approving reviews; minimum is 3")
}

// A policy with resource_findings must fan out into one finding per resource,
// each carrying its ResourceID + status and sharing the control's evidence
// digest. RunAll flattens them.
func TestRunControl_FansOutPerResource(t *testing.T) {
	c, err := controls.LoadFile("testdata/per-resource.yaml")
	require.NoError(t, err)
	l := controls.Loaded{Control: c, Path: "testdata/per-resource.yaml"}

	fs := New(policy.New(), evidence.NewFileCollector()).RunControl(context.Background(), l)
	require.Len(t, fs, 2, "one finding per user resource")

	byRes := map[string]apiv1.Finding{}
	for _, f := range fs {
		assert.Equal(t, "TEST-RES.1", f.ControlID)
		assert.NotEmpty(t, f.EvidenceFingerprint, "per-resource findings carry the control's evidence digest")
		byRes[f.ResourceID] = f
	}
	assert.Equal(t, apiv1.StatusPass, byRes["bucket-a"].Status)
	assert.Equal(t, apiv1.StatusFail, byRes["bucket-b"].Status)
	assert.Contains(t, byRes["bucket-b"].Messages, "bucket-b failed")

	// RunAll flattens per-resource findings across controls.
	all := New(policy.New(), evidence.NewFileCollector()).RunAll(context.Background(), []controls.Loaded{l})
	assert.Len(t, all, 2)
}
