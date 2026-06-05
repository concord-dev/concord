package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const credentialReportPollAttempts = 10

var credentialReportPollDelay = 2 * time.Second

func SetCredentialReportPollDelay(d time.Duration) { credentialReportPollDelay = d }

func (c *Collector) collectIAMAccountSummary(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := c.iam.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, wrapErr("get account summary", err)
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

func (c *Collector) collectIAMPasswordPolicy(ref apiv1.EvidenceRef) (any, error) {
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
		return nil, wrapErr("get account password policy", err)
	}
	p := out.PasswordPolicy
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"policy": map[string]any{
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
		},
	}, nil
}

func isNoPasswordPolicyError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "NoSuchEntity" || apiErr.ErrorCode() == "NoSuchEntityException"
	}
	return false
}

func (c *Collector) collectIAMCredentialReport(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if _, err := c.iam.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}); err != nil {
		return nil, wrapErr("generate credential report", err)
	}
	out, err := c.pollCredentialReport(ctx)
	if err != nil {
		return nil, err
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

func (c *Collector) pollCredentialReport(ctx context.Context) (*iam.GetCredentialReportOutput, error) {
	for i := 0; i < credentialReportPollAttempts; i++ {
		out, err := c.iam.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err == nil {
			if out == nil || len(out.Content) == 0 {
				return nil, fmt.Errorf("credential report empty")
			}
			return out, nil
		}
		if !isReportInProgressError(err) {
			return nil, wrapErr("get credential report", err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("credential report not ready before timeout: %w", ctx.Err())
		case <-time.After(credentialReportPollDelay):
		}
	}
	return nil, fmt.Errorf("credential report not ready after %d attempts", credentialReportPollAttempts)
}

func isReportInProgressError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "ReportInProgress" || apiErr.ErrorCode() == "ReportInProgressException"
	}
	return false
}

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
		users = append(users, parseCredentialReportRow(splitCSV(line), get, now))
	}
	return users, nil
}

func parseCredentialReportRow(row []string, get func([]string, string) string, now time.Time) map[string]any {
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
	return user
}

func splitCSV(line string) []string { return strings.Split(line, ",") }

func parseCSVBool(s string) bool { return strings.EqualFold(s, "true") }

func normalizeNA(s string) string {
	switch s {
	case "N/A", "no_information", "not_supported":
		return ""
	}
	return s
}

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
