package runner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/pkg/controls"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/policy"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const (
	cisAWSS3Path           = "controls/frameworks/cis-aws/2.1.1-s3-encryption.yaml"
	cisAWSNoRootKeysPath   = "controls/frameworks/cis-aws/1.4-no-root-access-keys.yaml"
	cisAWSRootMFAPath      = "controls/frameworks/cis-aws/1.5-root-mfa.yaml"
	cisAWSS3PABPath        = "controls/frameworks/cis-aws/2.1.5-s3-public-access-block.yaml"
	cisAWSCloudTrailPath   = "controls/frameworks/cis-aws/3.1-cloudtrail-multi-region.yaml"
)

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
	return runControlWithFixture(t, cisAWSS3Path, fixture)
}


func TestRunCISAWS_NoRootAccessKeys_Pass(t *testing.T) {
	f := runControlWithFixture(t, cisAWSNoRootKeysPath, "iam-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCISAWS_NoRootAccessKeys_FailWithRootKeyPresent(t *testing.T) {
	f := runControlWithFixture(t, cisAWSNoRootKeysPath, "iam-root-key-present.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `root account has 1 active access key(s); rotate to IAM user keys and delete the root keys immediately`)
}

func TestRunCISAWS_NoRootAccessKeys_WarnOnMFAGaps(t *testing.T) {
	f := runControlWithFixture(t, cisAWSNoRootKeysPath, "iam-mfa-gaps.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "MFA gaps are warnings not denies")
	assert.Contains(t, f.Warnings, "root account MFA is not enabled (covered separately by CIS-AWS-1.5 once implemented)")
	assert.Contains(t, f.Warnings, "only 8 of 12 IAM users have MFA devices configured")
}


func TestRunCISAWS_RootMFA_Pass(t *testing.T) {
	f := runControlWithFixture(t, cisAWSRootMFAPath, "iam-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCISAWS_RootMFA_FailWhenDisabled(t *testing.T) {
	f := runControlWithFixture(t, cisAWSRootMFAPath, "iam-mfa-gaps.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "root account MFA is not enabled — enable an MFA device on the root user immediately")
}


func TestRunCISAWS_S3PAB_Pass(t *testing.T) {
	f := runControlWithFixture(t, cisAWSS3PABPath, "s3-pab-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v", f.Messages)
}

func TestRunCISAWS_S3PAB_PartialFails(t *testing.T) {
	f := runControlWithFixture(t, cisAWSS3PABPath, "s3-pab-partial.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `bucket "concord-prod-data" has Public Access Block flag "block_public_policy" disabled`)
	assert.Contains(t, f.Messages, `bucket "concord-website-assets" has no Public Access Block configuration at all`)
}


func TestRunCISAWS_CloudTrail_Pass(t *testing.T) {
	f := runControlWithFixture(t, cisAWSCloudTrailPath, "cloudtrail-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCISAWS_CloudTrail_NotLoggingFailsWithWarning(t *testing.T) {
	f := runControlWithFixture(t, cisAWSCloudTrailPath, "cloudtrail-not-logging.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "no CloudTrail trail satisfies multi-region + logging + file-validation simultaneously")
	assert.Contains(t, f.Warnings, `trail "concord-main-trail" is multi-region but logging is currently stopped`)
}

func TestRunCISAWS_CloudTrail_SingleRegionFails(t *testing.T) {
	f := runControlWithFixture(t, cisAWSCloudTrailPath, "cloudtrail-single-region-only.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "no CloudTrail trail satisfies multi-region + logging + file-validation simultaneously")
}

func TestRunCISAWS_CloudTrail_EmptyFails(t *testing.T) {
	f := runControlWithFixture(t, cisAWSCloudTrailPath, "cloudtrail-empty.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "no CloudTrail trails exist in this account")
}


func runControlWithFixture(t *testing.T, controlRelPath, fixture string) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), controlRelPath)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)
	c.Spec.Evidence[0].Fixture = "./tests/fixtures/" + fixture
	r := New(policy.New(), evidence.NewFileCollector())
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
}
