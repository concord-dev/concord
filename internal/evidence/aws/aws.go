package aws

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

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type S3API interface {
	ListBuckets(ctx context.Context, in *s3.ListBucketsInput, opts ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, opts ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
}

type IAMAPI interface {
	GetAccountSummary(ctx context.Context, in *iam.GetAccountSummaryInput, opts ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GetAccountPasswordPolicy(ctx context.Context, in *iam.GetAccountPasswordPolicyInput, opts ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	GenerateCredentialReport(ctx context.Context, in *iam.GenerateCredentialReportInput, opts ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, in *iam.GetCredentialReportInput, opts ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
}

type CloudTrailAPI interface {
	DescribeTrails(ctx context.Context, in *cloudtrail.DescribeTrailsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

type Collector struct {
	s3         S3API
	iam        IAMAPI
	cloudtrail CloudTrailAPI
}

type Option func(*Collector)

func WithS3(api S3API) Option { return func(c *Collector) { c.s3 = api } }

func WithIAM(api IAMAPI) Option { return func(c *Collector) { c.iam = api } }

func WithCloudTrail(api CloudTrailAPI) Option { return func(c *Collector) { c.cloudtrail = api } }

func New(ctx context.Context, region string) (*Collector, error) {
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &Collector{
		s3:         s3.NewFromConfig(cfg),
		iam:        iam.NewFromConfig(cfg),
		cloudtrail: cloudtrail.NewFromConfig(cfg),
	}, nil
}

func NewWith(opts ...Option) *Collector {
	c := &Collector{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Collector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := c.iam.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return "", wrapErr("probe", err)
	}
	users := out.SummaryMap["Users"]
	return fmt.Sprintf("iam reachable (%d users)", users), nil
}

func (c *Collector) Collect(cctx evidence.Context, ref apiv1.EvidenceRef) (any, error) {
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
		return nil, fmt.Errorf("%w: aws collector does not handle type %q", evidence.ErrUnsupportedType, ref.Type)
	}
}

func wrapErr(stage string, err error) error {
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
