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
	GetAccountPasswordPolicy(ctx context.Context, in *iam.GetAccountPasswordPolicyInput, opts ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	GenerateCredentialReport(ctx context.Context, in *iam.GenerateCredentialReportInput, opts ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, in *iam.GetCredentialReportInput, opts ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
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

// Probe calls iam:GetAccountSummary as a low-cost reachability + auth check.
// Returns a human-friendly identifier (e.g. "iam account 123456789012") and
// any wrapped error suitable for surfacing in `concord doctor`.
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

// Collect dispatches based on ref.Type.
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
	// Credentials never resolved (no profile, no IMDS) — collapse the
	// SDK's chatty wrapping into a single actionable line.
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

// ---------------- IAM password policy ----------------

func (c *AWSCollector) collectIAMPasswordPolicy(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := c.iam.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		if isNoPasswordPolicyError(err) {
			return map[string]any{
				"fetched_at": time.Now().UTC().Format(time.RFC3339),
				"configured": false,
			}, nil
		}
		return nil, wrapAWSError("get account password policy", err)
	}
	p := out.PasswordPolicy
	policy := map[string]any{
		"configured":                     true,
		"minimum_password_length":        aws.ToInt32(p.MinimumPasswordLength),
		"require_symbols":                p.RequireSymbols,
		"require_numbers":                p.RequireNumbers,
		"require_uppercase_characters":   p.RequireUppercaseCharacters,
		"require_lowercase_characters":   p.RequireLowercaseCharacters,
		"allow_users_to_change_password": p.AllowUsersToChangePassword,
		"expire_passwords":               p.ExpirePasswords,
		"max_password_age":               aws.ToInt32(p.MaxPasswordAge),
		"password_reuse_prevention":      aws.ToInt32(p.PasswordReusePrevention),
		"hard_expiry":                    aws.ToBool(p.HardExpiry),
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"policy":     policy,
	}, nil
}

func isNoPasswordPolicyError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "NoSuchEntity" || apiErr.ErrorCode() == "NoSuchEntityException"
	}
	return false
}

// ---------------- IAM credential report ----------------

// credentialReportPollAttempts caps how long collectIAMCredentialReport will
// wait for a freshly-requested report to become ready. credentialReportPollDelay
// is a var (not const) so tests can shrink it.
const credentialReportPollAttempts = 10

var credentialReportPollDelay = 2 * time.Second

func (c *AWSCollector) collectIAMCredentialReport(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if _, err := c.iam.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}); err != nil {
		return nil, wrapAWSError("generate credential report", err)
	}

	var out *iam.GetCredentialReportOutput
	for i := 0; i < credentialReportPollAttempts; i++ {
		var err error
		out, err = c.iam.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err == nil {
			break
		}
		if !isReportInProgressError(err) {
			return nil, wrapAWSError("get credential report", err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("credential report not ready before timeout: %w", ctx.Err())
		case <-time.After(credentialReportPollDelay):
		}
	}
	if out == nil || len(out.Content) == 0 {
		return nil, fmt.Errorf("credential report empty after %d attempts", credentialReportPollAttempts)
	}

	users, err := parseCredentialReport(string(out.Content), time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("parsing credential report: %w", err)
	}
	generated := ""
	if out.GeneratedTime != nil {
		generated = out.GeneratedTime.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"fetched_at":   time.Now().UTC().Format(time.RFC3339),
		"generated_at": generated,
		"users":        users,
	}, nil
}

// SetCredentialReportPollDelay overrides the inter-attempt wait time. Test-only.
func SetCredentialReportPollDelay(d time.Duration) { credentialReportPollDelay = d }

func isReportInProgressError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "ReportInProgress" || apiErr.ErrorCode() == "ReportInProgressException"
	}
	return false
}

// parseCredentialReport turns the IAM credential report CSV into a slice of
// per-user maps. now is injected so tests can fix the "days ago" calculation.
func parseCredentialReport(csvData string, now time.Time) ([]map[string]any, error) {
	lines := strings.Split(strings.TrimSpace(csvData), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("expected header + at least one row, got %d line(s)", len(lines))
	}
	header := splitCSV(lines[0])
	idx := make(map[string]int, len(header))
	for i, h := range header {
		idx[h] = i
	}
	get := func(row []string, col string) string {
		i, ok := idx[col]
		if !ok || i >= len(row) {
			return ""
		}
		return row[i]
	}
	users := make([]map[string]any, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		row := splitCSV(line)
		user := map[string]any{
			"user":             get(row, "user"),
			"arn":              get(row, "arn"),
			"user_created":     get(row, "user_creation_time"),
			"password_enabled": parseCSVBool(get(row, "password_enabled")),
			"mfa_active":       parseCSVBool(get(row, "mfa_active")),
		}
		pwLast := normalizeNA(get(row, "password_last_used"))
		user["password_last_used"] = pwLast
		user["password_last_used_days_ago"] = daysAgo(pwLast, now)

		keys := []map[string]any{}
		for _, n := range []string{"1", "2"} {
			active := parseCSVBool(get(row, "access_key_"+n+"_active"))
			lastUsed := normalizeNA(get(row, "access_key_"+n+"_last_used_date"))
			lastRotated := normalizeNA(get(row, "access_key_"+n+"_last_rotated"))
			if !active && lastUsed == "" && lastRotated == "" {
				continue
			}
			keys = append(keys, map[string]any{
				"key_num":            n,
				"active":             active,
				"last_used_date":     lastUsed,
				"last_used_days_ago": daysAgo(lastUsed, now),
				"last_rotated":       lastRotated,
			})
		}
		user["access_keys"] = keys
		users = append(users, user)
	}
	return users, nil
}

// splitCSV is a minimal CSV splitter for IAM credential reports, which never
// contain quoted fields or escaped commas.
func splitCSV(line string) []string {
	return strings.Split(line, ",")
}

func parseCSVBool(s string) bool {
	return strings.EqualFold(s, "true")
}

// normalizeNA collapses the IAM credential report's various "no value here"
// markers to an empty string so downstream rules don't need to special-case
// every spelling.
func normalizeNA(s string) string {
	switch s {
	case "N/A", "no_information", "not_supported":
		return ""
	}
	return s
}

// daysAgo returns the integer number of days between when and now. Returns
// -1 when when is empty or "N/A" (the IAM marker for "never used").
func daysAgo(when string, now time.Time) int {
	if when == "" || when == "N/A" || when == "no_information" || when == "not_supported" {
		return -1
	}
	t, err := time.Parse(time.RFC3339, when)
	if err != nil {
		return -1
	}
	return int(now.Sub(t).Hours() / 24)
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
