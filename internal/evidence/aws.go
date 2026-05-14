package evidence

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// S3API is the subset of the AWS S3 client Concord depends on.
type S3API interface {
	ListBuckets(ctx context.Context, in *s3.ListBucketsInput, opts ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, opts ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

// IAMAPI is the subset of the AWS IAM client Concord depends on.
type IAMAPI interface {
	GetAccountSummary(ctx context.Context, in *iam.GetAccountSummaryInput, opts ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
}

// CloudTrailAPI is the subset of the AWS CloudTrail client Concord depends on.
type CloudTrailAPI interface {
	DescribeTrails(ctx context.Context, in *cloudtrail.DescribeTrailsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

// AWSCollector queries multiple AWS services for evidence.
type AWSCollector struct {
	s3         S3API
	iam        IAMAPI
	cloudtrail CloudTrailAPI
}

// AWSOption configures an AWSCollector. Used by tests to inject mocks.
type AWSOption func(*AWSCollector)

// WithS3 injects an S3 client.
func WithS3(api S3API) AWSOption { return func(c *AWSCollector) { c.s3 = api } }

// WithIAM injects an IAM client.
func WithIAM(api IAMAPI) AWSOption { return func(c *AWSCollector) { c.iam = api } }

// WithCloudTrail injects a CloudTrail client.
func WithCloudTrail(api CloudTrailAPI) AWSOption { return func(c *AWSCollector) { c.cloudtrail = api } }

// NewAWSCollector constructs an AWSCollector using the default AWS credential chain.
func NewAWSCollector(ctx context.Context, region string) (*AWSCollector, error) {
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &AWSCollector{
		s3:         s3.NewFromConfig(cfg),
		iam:        iam.NewFromConfig(cfg),
		cloudtrail: cloudtrail.NewFromConfig(cfg),
	}, nil
}

// NewAWSCollectorWith builds a collector around injected clients. Used in tests.
func NewAWSCollectorWith(opts ...AWSOption) *AWSCollector {
	c := &AWSCollector{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Collect dispatches based on ref.Type.
func (c *AWSCollector) Collect(cctx Context, ref apiv1.EvidenceRef) (any, error) {
	switch ref.Type {
	case "s3_bucket_encryption":
		return c.collectS3BucketEncryption(ref)
	case "s3_public_access_block":
		return c.collectS3PublicAccessBlock(ref)
	case "iam_account_summary":
		return c.collectIAMAccountSummary(ref)
	case "cloudtrail_trails":
		return c.collectCloudTrailTrails(ref)
	case "":
		return nil, fmt.Errorf("aws collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: aws collector does not handle type %q", ErrUnsupportedType, ref.Type)
	}
}

// ---------------- S3 encryption ----------------

func (c *AWSCollector) collectS3BucketEncryption(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	listOut, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, wrapAWSError("listing buckets", err)
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
			return nil, wrapAWSError(fmt.Sprintf("getting encryption for %s", name), err)
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
		rule := map[string]any{"bucket_key_enabled": aws.ToBool(r.BucketKeyEnabled)}
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

func isNoEncryptionError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError"
	}
	return false
}

// wrapAWSError improves AWS API error messages. AccessDenied errors are
// reduced to "missing IAM permission <action>" so users see immediately
// which IAM action to grant. Other errors propagate with a stage prefix.
func wrapAWSError(stage string, err error) error {
	if err == nil {
		return nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		if code == "AccessDenied" || code == "AccessDeniedException" {
			if action := extractDeniedAction(apiErr.ErrorMessage()); action != "" {
				return fmt.Errorf("%s: missing IAM permission %q — attach a policy with this action (see examples/iam-readonly-policy.json)", stage, action)
			}
			return fmt.Errorf("%s: access denied — %s", stage, apiErr.ErrorMessage())
		}
	}
	return fmt.Errorf("%s: %w", stage, err)
}

// extractDeniedAction pulls the IAM action name from an AccessDenied message like
// "User: arn:... is not authorized to perform: iam:GetAccountSummary on resource: * ..."
// Returns "" when the message is unparseable.
func extractDeniedAction(msg string) string {
	const marker = "is not authorized to perform: "
	i := strings.Index(msg, marker)
	if i < 0 {
		return ""
	}
	rest := msg[i+len(marker):]
	end := strings.IndexAny(rest, " \t\n")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// ---------------- S3 public access block ----------------

func (c *AWSCollector) collectS3PublicAccessBlock(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	listOut, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, wrapAWSError("listing buckets", err)
	}

	buckets := make([]map[string]any, 0, len(listOut.Buckets))
	for _, b := range listOut.Buckets {
		name := aws.ToString(b.Name)
		pab, err := c.s3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name})
		entry := map[string]any{"name": name}
		switch {
		case err == nil:
			entry["public_access_block"] = normalizePAB(pab)
		case isNoPABError(err):
			entry["public_access_block"] = map[string]any{
				"configured":              false,
				"block_public_acls":       false,
				"block_public_policy":     false,
				"ignore_public_acls":      false,
				"restrict_public_buckets": false,
			}
		default:
			return nil, wrapAWSError(fmt.Sprintf("getting public access block for %s", name), err)
		}
		buckets = append(buckets, entry)
	}

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"buckets":    buckets,
	}, nil
}

func normalizePAB(out *s3.GetPublicAccessBlockOutput) map[string]any {
	cfg := out.PublicAccessBlockConfiguration
	return map[string]any{
		"configured":              true,
		"block_public_acls":       aws.ToBool(cfg.BlockPublicAcls),
		"block_public_policy":     aws.ToBool(cfg.BlockPublicPolicy),
		"ignore_public_acls":      aws.ToBool(cfg.IgnorePublicAcls),
		"restrict_public_buckets": aws.ToBool(cfg.RestrictPublicBuckets),
	}
}

func isNoPABError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "NoSuchPublicAccessBlockConfiguration"
	}
	return false
}

// ---------------- IAM account summary ----------------

func (c *AWSCollector) collectIAMAccountSummary(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := c.iam.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, wrapAWSError("get account summary", err)
	}

	summary := map[string]any{}
	for k, v := range out.SummaryMap {
		summary[string(k)] = v
	}

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"summary":    summary,
	}, nil
}

// ---------------- CloudTrail ----------------

func (c *AWSCollector) collectCloudTrailTrails(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := c.cloudtrail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, wrapAWSError("describing trails", err)
	}

	trails := make([]map[string]any, 0, len(out.TrailList))
	for _, t := range out.TrailList {
		name := aws.ToString(t.Name)
		trail := map[string]any{
			"name":                        name,
			"s3_bucket":                   aws.ToString(t.S3BucketName),
			"is_multi_region":             aws.ToBool(t.IsMultiRegionTrail),
			"is_organization":             aws.ToBool(t.IsOrganizationTrail),
			"log_file_validation_enabled": aws.ToBool(t.LogFileValidationEnabled),
			"home_region":                 aws.ToString(t.HomeRegion),
		}

		status, err := c.cloudtrail.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN})
		if err != nil {
			return nil, wrapAWSError(fmt.Sprintf("getting status for trail %s", name), err)
		}
		trail["is_logging"] = aws.ToBool(status.IsLogging)
		trails = append(trails, trail)
	}

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"trails":     trails,
	}, nil
}
