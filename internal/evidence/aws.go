package evidence

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// S3API is the subset of the AWS S3 client Concord depends on. Extracted so
// the collector can be unit-tested without hitting AWS.
type S3API interface {
	ListBuckets(ctx context.Context, in *s3.ListBucketsInput, opts ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, opts ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
}

// AWSCollector queries AWS for evidence (S3 buckets today; more services later).
type AWSCollector struct {
	s3 S3API
}

// NewAWSCollector constructs an AWSCollector using the default AWS credential chain
// (env vars, ~/.aws/credentials, IAM role). Returns an error if config cannot be loaded.
func NewAWSCollector(ctx context.Context, region string) (*AWSCollector, error) {
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &AWSCollector{s3: s3.NewFromConfig(cfg)}, nil
}

// NewAWSCollectorWith builds a collector around an injected S3 client. Use in tests.
func NewAWSCollectorWith(s3api S3API) *AWSCollector {
	return &AWSCollector{s3: s3api}
}

// Collect dispatches based on ref.Type.
func (c *AWSCollector) Collect(cctx Context, ref apiv1.EvidenceRef) (any, error) {
	switch ref.Type {
	case "s3_bucket_encryption":
		return c.collectS3BucketEncryption(ref)
	case "":
		return nil, fmt.Errorf("aws collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: aws collector does not handle type %q", ErrUnsupportedType, ref.Type)
	}
}

func (c *AWSCollector) collectS3BucketEncryption(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	listOut, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	buckets := make([]map[string]any, 0, len(listOut.Buckets))
	for _, b := range listOut.Buckets {
		name := aws.ToString(b.Name)
		bucket := map[string]any{"name": name}
		if b.CreationDate != nil {
			bucket["creation_date"] = b.CreationDate.UTC().Format(time.RFC3339)
		}

		encOut, err := c.s3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: b.Name})
		switch {
		case err == nil:
			bucket["encryption"] = normalizeEncryption(encOut)
		case isNoEncryptionError(err):
			bucket["encryption"] = map[string]any{"configured": false, "rules": []any{}}
		default:
			return nil, fmt.Errorf("getting encryption for %s: %w", name, err)
		}

		buckets = append(buckets, bucket)
	}

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"buckets":    buckets,
	}, nil
}

func normalizeEncryption(out *s3.GetBucketEncryptionOutput) map[string]any {
	result := map[string]any{"configured": true, "rules": []map[string]any{}}
	if out == nil || out.ServerSideEncryptionConfiguration == nil {
		return result
	}
	rules := make([]map[string]any, 0, len(out.ServerSideEncryptionConfiguration.Rules))
	for _, r := range out.ServerSideEncryptionConfiguration.Rules {
		rule := map[string]any{
			"bucket_key_enabled": aws.ToBool(r.BucketKeyEnabled),
		}
		if r.ApplyServerSideEncryptionByDefault != nil {
			rule["sse_algorithm"] = string(r.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
			if r.ApplyServerSideEncryptionByDefault.KMSMasterKeyID != nil {
				rule["kms_key"] = aws.ToString(r.ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
			}
		}
		rules = append(rules, rule)
	}
	result["rules"] = rules
	return result
}

// isNoEncryptionError detects AWS's "no encryption configured" response,
// which arrives as an API error with code ServerSideEncryptionConfigurationNotFoundError.
func isNoEncryptionError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError"
	}
	return false
}
