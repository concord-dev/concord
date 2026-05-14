package evidence_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type mockS3 struct {
	listOut *s3.ListBucketsOutput
	listErr error
	enc     map[string]encResult
}

type encResult struct {
	out *s3.GetBucketEncryptionOutput
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

// notFoundErr fakes the AWS "no encryption" API error.
type notFoundErr struct{}

func (e *notFoundErr) Error() string                 { return "ServerSideEncryptionConfigurationNotFoundError" }
func (e *notFoundErr) ErrorCode() string             { return "ServerSideEncryptionConfigurationNotFoundError" }
func (e *notFoundErr) ErrorMessage() string          { return "no encryption configured" }
func (e *notFoundErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestAWSCollector_S3_PassWithKMS(t *testing.T) {
	created := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	m := &mockS3{
		listOut: &s3.ListBucketsOutput{
			Buckets: []s3types.Bucket{
				{Name: aws.String("prod-data"), CreationDate: aws.Time(created)},
			},
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

	c := evidence.NewAWSCollectorWith(m)
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "aws", Type: "s3_bucket_encryption",
	})
	require.NoError(t, err)

	out := v.(map[string]any)
	buckets := out["buckets"].([]map[string]any)
	require.Len(t, buckets, 1)
	assert.Equal(t, "prod-data", buckets[0]["name"])
	assert.Equal(t, "2025-03-01T00:00:00Z", buckets[0]["creation_date"])

	enc := buckets[0]["encryption"].(map[string]any)
	assert.Equal(t, true, enc["configured"])

	rules := enc["rules"].([]map[string]any)
	require.Len(t, rules, 1)
	assert.Equal(t, "aws:kms", rules[0]["sse_algorithm"])
	assert.Equal(t, "arn:aws:kms:us-east-1:123:key/abc", rules[0]["kms_key"])
	assert.Equal(t, true, rules[0]["bucket_key_enabled"])
}

func TestAWSCollector_S3_UnconfiguredEncryption(t *testing.T) {
	m := &mockS3{
		listOut: &s3.ListBucketsOutput{
			Buckets: []s3types.Bucket{
				{Name: aws.String("encrypted")},
				{Name: aws.String("naked")},
			},
		},
		enc: map[string]encResult{
			"encrypted": {out: &s3.GetBucketEncryptionOutput{
				ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
					Rules: []s3types.ServerSideEncryptionRule{
						{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{SSEAlgorithm: s3types.ServerSideEncryptionAwsKms}},
					},
				},
			}},
			"naked": {err: &notFoundErr{}},
		},
	}

	c := evidence.NewAWSCollectorWith(m)
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "aws", Type: "s3_bucket_encryption",
	})
	require.NoError(t, err)

	buckets := v.(map[string]any)["buckets"].([]map[string]any)
	require.Len(t, buckets, 2)

	encrypted := buckets[0]["encryption"].(map[string]any)
	assert.Equal(t, true, encrypted["configured"])

	naked := buckets[1]["encryption"].(map[string]any)
	assert.Equal(t, false, naked["configured"])
}

func TestAWSCollector_S3_ListBucketsErrorPropagates(t *testing.T) {
	m := &mockS3{listErr: errors.New("access denied")}
	c := evidence.NewAWSCollectorWith(m)
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "aws", Type: "s3_bucket_encryption",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestAWSCollector_S3_OtherEncryptionErrorPropagates(t *testing.T) {
	m := &mockS3{
		listOut: &s3.ListBucketsOutput{
			Buckets: []s3types.Bucket{{Name: aws.String("b")}},
		},
		enc: map[string]encResult{
			"b": {err: errors.New("throttled")},
		},
	}
	c := evidence.NewAWSCollectorWith(m)
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "aws", Type: "s3_bucket_encryption",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "throttled")
}

func TestAWSCollector_UnknownTypeReturnsUnsupported(t *testing.T) {
	c := evidence.NewAWSCollectorWith(&mockS3{})
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "aws", Type: "weird",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, evidence.ErrUnsupportedType))
}

func TestAWSCollector_EmptyTypeErrors(t *testing.T) {
	c := evidence.NewAWSCollectorWith(&mockS3{})
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "aws"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}
