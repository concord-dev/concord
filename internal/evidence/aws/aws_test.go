package aws_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	awsev "github.com/concord-dev/concord/internal/evidence/aws"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// --- Mocks ---

type mockS3 struct {
	listOut *s3.ListBucketsOutput
	listErr error
	enc     map[string]encResult
	pab     map[string]pabResult
}

type encResult struct {
	out *s3.GetBucketEncryptionOutput
	err error
}

type pabResult struct {
	out *s3.GetPublicAccessBlockOutput
	err error
}

func (m *mockS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return m.listOut, m.listErr
}

func (m *mockS3) GetBucketEncryption(_ context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	r, ok := m.enc[aws.ToString(in.Bucket)]
	if !ok {
		return nil, errors.New("test setup: bucket not in mock")
	}
	return r.out, r.err
}

func (m *mockS3) GetPublicAccessBlock(_ context.Context, in *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	r, ok := m.pab[aws.ToString(in.Bucket)]
	if !ok {
		return nil, errors.New("test setup: bucket not in pab mock")
	}
	return r.out, r.err
}

type mockIAM struct {
	out *iam.GetAccountSummaryOutput
	err error

	policyOut *iam.GetAccountPasswordPolicyOutput
	policyErr error

	generateErr  error
	reportOut    *iam.GetCredentialReportOutput
	reportErr    error
	reportErrSeq []error
	reportCalls  int
}

func (m *mockIAM) GetAccountSummary(_ context.Context, _ *iam.GetAccountSummaryInput, _ ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return m.out, m.err
}

func (m *mockIAM) GetAccountPasswordPolicy(_ context.Context, _ *iam.GetAccountPasswordPolicyInput, _ ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	return m.policyOut, m.policyErr
}

func (m *mockIAM) GenerateCredentialReport(_ context.Context, _ *iam.GenerateCredentialReportInput, _ ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	return &iam.GenerateCredentialReportOutput{}, m.generateErr
}

func (m *mockIAM) GetCredentialReport(_ context.Context, _ *iam.GetCredentialReportInput, _ ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	defer func() { m.reportCalls++ }()
	if m.reportCalls < len(m.reportErrSeq) {
		return nil, m.reportErrSeq[m.reportCalls]
	}
	return m.reportOut, m.reportErr
}

type mockCloudTrail struct {
	describeOut *cloudtrail.DescribeTrailsOutput
	describeErr error
	status      map[string]*cloudtrail.GetTrailStatusOutput
}

func (m *mockCloudTrail) DescribeTrails(_ context.Context, _ *cloudtrail.DescribeTrailsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return m.describeOut, m.describeErr
}

func (m *mockCloudTrail) GetTrailStatus(_ context.Context, in *cloudtrail.GetTrailStatusInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	if s, ok := m.status[aws.ToString(in.Name)]; ok {
		return s, nil
	}
	return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(false)}, nil
}

type errCode struct{ code string }

func (e *errCode) Error() string                 { return e.code }
func (e *errCode) ErrorCode() string             { return e.code }
func (e *errCode) ErrorMessage() string          { return e.code }
func (e *errCode) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// --- S3 encryption tests ---

func TestCollector_S3_PassWithKMS(t *testing.T) {
	created := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	m := &mockS3{
		listOut: &s3.ListBucketsOutput{
			Buckets: []s3types.Bucket{{Name: aws.String("prod-data"), CreationDate: aws.Time(created)}},
		},
		enc: map[string]encResult{
			"prod-data": {out: &s3.GetBucketEncryptionOutput{
				ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
					Rules: []s3types.ServerSideEncryptionRule{
						{
							ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
								SSEAlgorithm:   s3types.ServerSideEncryptionAwsKms,
								KMSMasterKeyID: aws.String("arn:aws:kms:us-east-1:123:key/abc"),
							},
							BucketKeyEnabled: aws.Bool(true),
						},
					},
				},
			}},
		},
	}

	c := awsev.NewWith(awsev.WithS3(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "s3_bucket_encryption"})
	require.NoError(t, err)

	buckets := v.(map[string]any)["buckets"].([]map[string]any)
	require.Len(t, buckets, 1)
	enc := buckets[0]["encryption"].(map[string]any)
	assert.Equal(t, true, enc["configured"])

	rules := enc["rules"].([]map[string]any)
	require.Len(t, rules, 1)
	assert.Equal(t, "aws:kms", rules[0]["sse_algorithm"])
}

func TestCollector_S3_UnconfiguredEncryption(t *testing.T) {
	m := &mockS3{
		listOut: &s3.ListBucketsOutput{
			Buckets: []s3types.Bucket{{Name: aws.String("encrypted")}, {Name: aws.String("naked")}},
		},
		enc: map[string]encResult{
			"encrypted": {out: &s3.GetBucketEncryptionOutput{
				ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
					Rules: []s3types.ServerSideEncryptionRule{
						{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms}},
					},
				},
			}},
			"naked": {err: &errCode{code: "ServerSideEncryptionConfigurationNotFoundError"}},
		},
	}
	c := awsev.NewWith(awsev.WithS3(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "s3_bucket_encryption"})
	require.NoError(t, err)
	buckets := v.(map[string]any)["buckets"].([]map[string]any)
	assert.Equal(t, true, buckets[0]["encryption"].(map[string]any)["configured"])
	assert.Equal(t, false, buckets[1]["encryption"].(map[string]any)["configured"])
}

func TestCollector_S3_ListBucketsErrorPropagates(t *testing.T) {
	c := awsev.NewWith(awsev.WithS3(&mockS3{listErr: errors.New("access denied")}))
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "s3_bucket_encryption"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// accessDeniedErr fakes the smithy.APIError shape AWS returns on 403.
type accessDeniedErr struct{ msg string }

func (e *accessDeniedErr) Error() string                 { return e.msg }
func (e *accessDeniedErr) ErrorCode() string             { return "AccessDenied" }
func (e *accessDeniedErr) ErrorMessage() string          { return e.msg }
func (e *accessDeniedErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestCollector_AccessDeniedSurfacesIAMAction(t *testing.T) {
	m := &mockS3{listErr: &accessDeniedErr{
		msg: "User: arn:aws:iam::123:user/x is not authorized to perform: s3:ListAllMyBuckets because no identity-based policy allows the s3:ListAllMyBuckets action",
	}}
	c := awsev.NewWith(awsev.WithS3(m))
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "s3_bucket_encryption"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `missing IAM permission "s3:ListAllMyBuckets"`)
	assert.Contains(t, err.Error(), "examples/iam-readonly-policy.json")
	assert.NotContains(t, err.Error(), "arn:aws:iam::")
}

// --- S3 public access block tests ---

func TestCollector_S3_PublicAccessBlock_AllConfigured(t *testing.T) {
	m := &mockS3{
		listOut: &s3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: aws.String("secured")}}},
		pab: map[string]pabResult{
			"secured": {out: &s3.GetPublicAccessBlockOutput{
				PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
					BlockPublicAcls:       aws.Bool(true),
					BlockPublicPolicy:     aws.Bool(true),
					IgnorePublicAcls:      aws.Bool(true),
					RestrictPublicBuckets: aws.Bool(true),
				},
			}},
		},
	}
	c := awsev.NewWith(awsev.WithS3(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "s3_public_access_block"})
	require.NoError(t, err)

	pab := v.(map[string]any)["buckets"].([]map[string]any)[0]["public_access_block"].(map[string]any)
	assert.Equal(t, true, pab["configured"])
	assert.Equal(t, true, pab["block_public_acls"])
	assert.Equal(t, true, pab["block_public_policy"])
}

func TestCollector_S3_PublicAccessBlock_NotConfigured(t *testing.T) {
	m := &mockS3{
		listOut: &s3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: aws.String("naked")}}},
		pab: map[string]pabResult{
			"naked": {err: &errCode{code: "NoSuchPublicAccessBlockConfiguration"}},
		},
	}
	c := awsev.NewWith(awsev.WithS3(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "s3_public_access_block"})
	require.NoError(t, err)

	pab := v.(map[string]any)["buckets"].([]map[string]any)[0]["public_access_block"].(map[string]any)
	assert.Equal(t, false, pab["configured"])
	assert.Equal(t, false, pab["block_public_acls"])
}

// --- IAM account summary ---

func TestCollector_IAM_AccountSummary(t *testing.T) {
	m := &mockIAM{out: &iam.GetAccountSummaryOutput{
		SummaryMap: map[string]int32{
			"AccountAccessKeysPresent": 0,
			"AccountMFAEnabled":        1,
			"Users":                    12,
			"MFADevicesInUse":          11,
		},
	}}
	c := awsev.NewWith(awsev.WithIAM(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "iam_account_summary"})
	require.NoError(t, err)

	summary := v.(map[string]any)["summary"].(map[string]any)
	assert.EqualValues(t, 0, summary["AccountAccessKeysPresent"])
	assert.EqualValues(t, 1, summary["AccountMFAEnabled"])
	assert.EqualValues(t, 12, summary["Users"])
}

func TestCollector_IAM_ErrorPropagates(t *testing.T) {
	c := awsev.NewWith(awsev.WithIAM(&mockIAM{err: errors.New("access denied")}))
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "iam_account_summary"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestCollector_Probe(t *testing.T) {
	m := &mockIAM{out: &iam.GetAccountSummaryOutput{SummaryMap: map[string]int32{"Users": 7}}}
	c := awsev.NewWith(awsev.WithIAM(m))
	info, err := c.Probe(context.Background())
	require.NoError(t, err)
	assert.Contains(t, info, "7 users")
}

func TestCollector_Probe_WrapsAccessDenied(t *testing.T) {
	c := awsev.NewWith(awsev.WithIAM(&mockIAM{err: &errCode{code: "AccessDenied"}}))
	_, err := c.Probe(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// --- CloudTrail ---

func TestCollector_CloudTrail_MultiRegionLogging(t *testing.T) {
	m := &mockCloudTrail{
		describeOut: &cloudtrail.DescribeTrailsOutput{
			TrailList: []cttypes.Trail{
				{
					Name:                     aws.String("main"),
					TrailARN:                 aws.String("arn:aws:cloudtrail:us-east-1:123:trail/main"),
					S3BucketName:             aws.String("concord-cloudtrail"),
					IsMultiRegionTrail:       aws.Bool(true),
					IsOrganizationTrail:      aws.Bool(false),
					LogFileValidationEnabled: aws.Bool(true),
					HomeRegion:               aws.String("us-east-1"),
				},
			},
		},
		status: map[string]*cloudtrail.GetTrailStatusOutput{
			"arn:aws:cloudtrail:us-east-1:123:trail/main": {IsLogging: aws.Bool(true)},
		},
	}
	c := awsev.NewWith(awsev.WithCloudTrail(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "cloudtrail_trails"})
	require.NoError(t, err)

	trails := v.(map[string]any)["trails"].([]map[string]any)
	require.Len(t, trails, 1)
	assert.Equal(t, "main", trails[0]["name"])
	assert.Equal(t, true, trails[0]["is_multi_region"])
	assert.Equal(t, true, trails[0]["log_file_validation_enabled"])
	assert.Equal(t, true, trails[0]["is_logging"])
}

func TestCollector_CloudTrail_NotLogging(t *testing.T) {
	m := &mockCloudTrail{
		describeOut: &cloudtrail.DescribeTrailsOutput{
			TrailList: []cttypes.Trail{
				{Name: aws.String("stopped"), TrailARN: aws.String("arn:1"), IsMultiRegionTrail: aws.Bool(true)},
			},
		},
		status: map[string]*cloudtrail.GetTrailStatusOutput{
			"arn:1": {IsLogging: aws.Bool(false)},
		},
	}
	c := awsev.NewWith(awsev.WithCloudTrail(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "cloudtrail_trails"})
	require.NoError(t, err)

	trails := v.(map[string]any)["trails"].([]map[string]any)
	assert.Equal(t, false, trails[0]["is_logging"])
}

func TestCollector_CloudTrail_NoTrails(t *testing.T) {
	m := &mockCloudTrail{describeOut: &cloudtrail.DescribeTrailsOutput{TrailList: nil}}
	c := awsev.NewWith(awsev.WithCloudTrail(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "cloudtrail_trails"})
	require.NoError(t, err)
	assert.Empty(t, v.(map[string]any)["trails"])
}

// --- IAM password policy ---

func TestCollector_IAM_PasswordPolicy_Present(t *testing.T) {
	m := &mockIAM{policyOut: &iam.GetAccountPasswordPolicyOutput{
		PasswordPolicy: &iamtypes.PasswordPolicy{
			MinimumPasswordLength:      aws.Int32(14),
			RequireSymbols:             true,
			RequireNumbers:             true,
			RequireUppercaseCharacters: true,
			RequireLowercaseCharacters: true,
			AllowUsersToChangePassword: true,
			ExpirePasswords:            true,
			MaxPasswordAge:             aws.Int32(90),
			PasswordReusePrevention:    aws.Int32(24),
			HardExpiry:                 aws.Bool(false),
		},
	}}
	c := awsev.NewWith(awsev.WithIAM(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "iam_password_policy"})
	require.NoError(t, err)

	policy := v.(map[string]any)["policy"].(map[string]any)
	assert.Equal(t, true, policy["configured"])
	assert.EqualValues(t, 14, policy["minimum_password_length"])
	assert.Equal(t, true, policy["require_symbols"])
	assert.EqualValues(t, 90, policy["max_password_age"])
	assert.EqualValues(t, 24, policy["password_reuse_prevention"])
}

func TestCollector_IAM_PasswordPolicy_NoSuchEntityReturnsUnconfigured(t *testing.T) {
	m := &mockIAM{policyErr: &errCode{code: "NoSuchEntity"}}
	c := awsev.NewWith(awsev.WithIAM(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "iam_password_policy"})
	require.NoError(t, err, "missing policy is data, not an error")
	assert.Equal(t, false, v.(map[string]any)["configured"])
}

func TestCollector_IAM_PasswordPolicy_OtherErrorsPropagate(t *testing.T) {
	m := &mockIAM{policyErr: errors.New("network down")}
	c := awsev.NewWith(awsev.WithIAM(m))
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "iam_password_policy"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network down")
}

// --- IAM credential report ---

func TestCollector_IAM_CredentialReport_HappyPath(t *testing.T) {
	generated := time.Date(2026, 5, 14, 9, 55, 0, 0, time.UTC)
	csv := "user,arn,user_creation_time,password_enabled,password_last_used,mfa_active,access_key_1_active,access_key_1_last_used_date,access_key_1_last_rotated,access_key_2_active,access_key_2_last_used_date,access_key_2_last_rotated\n" +
		"<root_account>,arn:aws:iam::123:root,2024-01-01T00:00:00+00:00,false,2026-05-12T08:00:00+00:00,true,false,N/A,N/A,false,N/A,N/A\n" +
		"alice,arn:aws:iam::123:user/alice,2025-02-10T00:00:00+00:00,true,2026-05-14T07:00:00+00:00,true,true,2026-05-13T22:30:00+00:00,2026-03-01T00:00:00+00:00,false,N/A,N/A\n"

	m := &mockIAM{
		reportOut: &iam.GetCredentialReportOutput{
			Content:       []byte(csv),
			GeneratedTime: aws.Time(generated),
		},
	}
	c := awsev.NewWith(awsev.WithIAM(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "iam_credential_report"})
	require.NoError(t, err)

	out := v.(map[string]any)
	assert.Equal(t, "2026-05-14T09:55:00Z", out["generated_at"])
	users := out["users"].([]map[string]any)
	require.Len(t, users, 2)
	assert.Equal(t, "<root_account>", users[0]["user"])
	assert.Equal(t, false, users[0]["password_enabled"])

	alice := users[1]
	assert.Equal(t, "alice", alice["user"])
	assert.Equal(t, true, alice["password_enabled"])
	assert.Equal(t, true, alice["mfa_active"])
	keys := alice["access_keys"].([]map[string]any)
	require.Len(t, keys, 1, "only the active key #1 should appear; #2 is fully absent")
	assert.Equal(t, "1", keys[0]["key_num"])
	assert.Equal(t, true, keys[0]["active"])
}

func TestCollector_IAM_CredentialReport_PollsUntilReady(t *testing.T) {
	awsev.SetCredentialReportPollDelay(5 * time.Millisecond)
	t.Cleanup(func() { awsev.SetCredentialReportPollDelay(2 * time.Second) })

	csv := "user,arn,user_creation_time,password_enabled,password_last_used,mfa_active,access_key_1_active,access_key_1_last_used_date,access_key_1_last_rotated\nbob,arn,2025-01-01T00:00:00+00:00,false,N/A,false,false,N/A,N/A\n"
	m := &mockIAM{
		reportErrSeq: []error{&errCode{code: "ReportInProgress"}, &errCode{code: "ReportInProgress"}},
		reportOut:    &iam.GetCredentialReportOutput{Content: []byte(csv), GeneratedTime: aws.Time(time.Now())},
	}
	c := awsev.NewWith(awsev.WithIAM(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "iam_credential_report"})
	require.NoError(t, err)
	assert.Len(t, v.(map[string]any)["users"], 1)
	assert.Equal(t, 3, m.reportCalls, "should poll past the two ReportInProgress responses before succeeding")
}

func TestCollector_IAM_CredentialReport_GenerateErrorPropagates(t *testing.T) {
	m := &mockIAM{generateErr: &errCode{code: "AccessDenied"}}
	c := awsev.NewWith(awsev.WithIAM(m))
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "iam_credential_report"})
	require.Error(t, err)
}

// --- Dispatch ---

func TestCollector_UnknownTypeReturnsUnsupported(t *testing.T) {
	c := awsev.NewWith()
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "weird"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, evidence.ErrUnsupportedType))
}

func TestCollector_EmptyTypeErrors(t *testing.T) {
	c := awsev.NewWith()
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}
