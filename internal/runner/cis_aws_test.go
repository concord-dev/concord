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

const cisAWSS3Path = "controls/frameworks/cis-aws/2.1.1-s3-encryption.yaml"

func TestRunCISAWS_S3_Pass(t *testing.T) {
	f := runCISAWSS3(t, "s3-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
	assert.Empty(t, f.Messages)
	assert.Empty(t, f.Warnings)
}

func TestRunCISAWS_S3_Unencrypted(t *testing.T) {
	f := runCISAWSS3(t, "s3-unencrypted.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `bucket "concord-temp-uploads" has no server-side encryption configured`)
	assert.Len(t, f.Messages, 1, "only the unencrypted bucket should fail; messages=%v", f.Messages)
}

func TestRunCISAWS_S3_AES256Warning(t *testing.T) {
	f := runCISAWSS3(t, "s3-aes256-warning.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "AES256 should warn, not fail; messages=%v", f.Messages)
	assert.Contains(t, f.Warnings, `bucket "concord-legacy-backups" uses AES256 (consider aws:kms for stronger key management)`)
	assert.Contains(t, f.Warnings, `bucket "concord-kms-no-bucket-key" uses KMS without bucket-key enabled (consider enabling to lower KMS costs)`)
}

func runCISAWSS3(t *testing.T, fixture string) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), cisAWSS3Path)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)

	c.Spec.Evidence[0].Fixture = "./tests/fixtures/" + fixture

	r := New(policy.New(), evidence.NewFileCollector())
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
}
