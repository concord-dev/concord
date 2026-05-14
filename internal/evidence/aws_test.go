package evidence_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
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
}

func (m *mockIAM) GetAccountSummary(_ context.Context, _ *iam.GetAccountSummaryInput, _ ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return m.out, m.err
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

// errCode fakes an arbitrary AWS API error.
type errCode struct{ code string }

func (e *errCode) Error() string                 { return e.code }
func (e *errCode) ErrorCode() string             { return e.code }
func (e *errCode) ErrorMessage() string          { return e.code }
func (e *errCode) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// --- S3 encryption tests ---

func TestAWSCollector_S3_PassWithKMS(t *testing.T) {
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

	c := evidence.NewAWSCollectorWith(evidence.WithS3(m))
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

func TestAWSCollector_S3_UnconfiguredEncryption(t *testing.T) {
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
	c := evidence.NewAWSCollectorWith(evidence.WithS3(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "s3_bucket_encryption"})
	require.NoError(t, err)
	buckets := v.(map[string]any)["buckets"].([]map[string]any)
	assert.Equal(t, true, buckets[0]["encryption"].(map[string]any)["configured"])
	assert.Equal(t, false, buckets[1]["encryption"].(map[string]any)["configured"])
}

func TestAWSCollector_S3_ListBucketsErrorPropagates(t *testing.T) {
	c := evidence.NewAWSCollectorWith(evidence.WithS3(&mockS3{listErr: errors.New("access denied")}))
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "s3_bucket_encryption"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// --- S3 public access block tests ---

func TestAWSCollector_S3_PublicAccessBlock_AllConfigured(t *testing.T) {
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
	c := evidence.NewAWSCollectorWith(evidence.WithS3(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "s3_public_access_block"})
	require.NoError(t, err)

	pab := v.(map[string]any)["buckets"].([]map[string]any)[0]["public_access_block"].(map[string]any)
	assert.Equal(t, true, pab["configured"])
	assert.Equal(t, true, pab["block_public_acls"])
	assert.Equal(t, true, pab["block_public_policy"])
}

func TestAWSCollector_S3_PublicAccessBlock_NotConfigured(t *testing.T) {
	m := &mockS3{
		listOut: &s3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: aws.String("naked")}}},
		pab: map[string]pabResult{
			"naked": {err: &errCode{code: "NoSuchPublicAccessBlockConfiguration"}},
		},
	}
	c := evidence.NewAWSCollectorWith(evidence.WithS3(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "s3_public_access_block"})
	require.NoError(t, err)

	pab := v.(map[string]any)["buckets"].([]map[string]any)[0]["public_access_block"].(map[string]any)
	assert.Equal(t, false, pab["configured"])
	assert.Equal(t, false, pab["block_public_acls"])
}

// --- IAM account summary ---

func TestAWSCollector_IAM_AccountSummary(t *testing.T) {
	m := &mockIAM{out: &iam.GetAccountSummaryOutput{
		SummaryMap: map[string]int32{
			"AccountAccessKeysPresent": 0,
			"AccountMFAEnabled":        1,
			"Users":                    12,
			"MFADevicesInUse":          11,
		},
	}}
	c := evidence.NewAWSCollectorWith(evidence.WithIAM(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "iam_account_summary"})
	require.NoError(t, err)

	summary := v.(map[string]any)["summary"].(map[string]any)
	assert.EqualValues(t, 0, summary["AccountAccessKeysPresent"])
	assert.EqualValues(t, 1, summary["AccountMFAEnabled"])
	assert.EqualValues(t, 12, summary["Users"])
}

func TestAWSCollector_IAM_ErrorPropagates(t *testing.T) {
	c := evidence.NewAWSCollectorWith(evidence.WithIAM(&mockIAM{err: errors.New("access denied")}))
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "iam_account_summary"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

// --- CloudTrail ---

func TestAWSCollector_CloudTrail_MultiRegionLogging(t *testing.T) {
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
	c := evidence.NewAWSCollectorWith(evidence.WithCloudTrail(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "cloudtrail_trails"})
	require.NoError(t, err)

	trails := v.(map[string]any)["trails"].([]map[string]any)
	require.Len(t, trails, 1)
	assert.Equal(t, "main", trails[0]["name"])
	assert.Equal(t, true, trails[0]["is_multi_region"])
	assert.Equal(t, true, trails[0]["log_file_validation_enabled"])
	assert.Equal(t, true, trails[0]["is_logging"])
}

func TestAWSCollector_CloudTrail_NotLogging(t *testing.T) {
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
	c := evidence.NewAWSCollectorWith(evidence.WithCloudTrail(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "cloudtrail_trails"})
	require.NoError(t, err)

	trails := v.(map[string]any)["trails"].([]map[string]any)
	assert.Equal(t, false, trails[0]["is_logging"])
}

func TestAWSCollector_CloudTrail_NoTrails(t *testing.T) {
	m := &mockCloudTrail{describeOut: &cloudtrail.DescribeTrailsOutput{TrailList: nil}}
	c := evidence.NewAWSCollectorWith(evidence.WithCloudTrail(m))
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "cloudtrail_trails"})
	require.NoError(t, err)
	assert.Empty(t, v.(map[string]any)["trails"])
}

// --- Dispatch ---

func TestAWSCollector_UnknownTypeReturnsUnsupported(t *testing.T) {
	c := evidence.NewAWSCollectorWith()
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws", Type: "weird"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, evidence.ErrUnsupportedType))
}

func TestAWSCollector_EmptyTypeErrors(t *testing.T) {
	c := evidence.NewAWSCollectorWith()
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}
