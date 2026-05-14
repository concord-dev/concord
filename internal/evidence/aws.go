package evidence

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
	GetAccountPasswordPolicy(ctx context.Context, in *iam.GetAccountPasswordPolicyInput, opts ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	GenerateCredentialReport(ctx context.Context, in *iam.GenerateCredentialReportInput, opts ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, in *iam.GetCredentialReportInput, opts ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
}

// CloudTrailAPI is the subset of the AWS CloudTrail client Concord depends on.
type CloudTrailAPI interface {
	DescribeTrails(ctx context.Context, in *cloudtrail.DescribeTrailsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

// AWSCollector queries multiple AWS services for evidence. Each service-
// specific Collect helper lives in its own file (aws_s3.go, aws_iam.go,
// aws_cloudtrail.go); this file owns construction + dispatch.
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

// Probe calls iam:GetAccountSummary as a low-cost reachability + auth check.
// Returns a human-friendly identifier and any wrapped error suitable for
// surfacing in `concord doctor`.
func (c *AWSCollector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := c.iam.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return "", wrapAWSError("probe", err)
	}
	users := out.SummaryMap["Users"]
	return fmt.Sprintf("iam reachable (%d users)", users), nil
}

// Collect dispatches based on ref.Type to the per-service collector method.
func (c *AWSCollector) Collect(cctx Context, ref apiv1.EvidenceRef) (any, error) {
	switch ref.Type {
	case "s3_bucket_encryption":
		return c.collectS3BucketEncryption(ref)
	case "s3_public_access_block":
		return c.collectS3PublicAccessBlock(ref)
	case "iam_account_summary":
		return c.collectIAMAccountSummary(ref)
	case "iam_password_policy":
		return c.collectIAMPasswordPolicy(ref)
	case "iam_credential_report":
		return c.collectIAMCredentialReport(ref)
	case "cloudtrail_trails":
		return c.collectCloudTrailTrails(ref)
	case "":
		return nil, fmt.Errorf("aws collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: aws collector does not handle type %q", ErrUnsupportedType, ref.Type)
	}
}

// wrapAWSError improves AWS API error messages. AccessDenied errors are
// reduced to "missing IAM permission <action>" so users see immediately
// which IAM action to grant. Credential-resolution failures get collapsed
// into a single actionable line.
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
	if msg := err.Error(); strings.Contains(msg, "failed to refresh cached credentials") || strings.Contains(msg, "no EC2 IMDS role found") {
		return fmt.Errorf("%s: no usable AWS credentials — set AWS_PROFILE, AWS_ACCESS_KEY_ID, or run from an instance with an IAM role", stage)
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
