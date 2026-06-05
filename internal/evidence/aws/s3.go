package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func (c *Collector) collectS3BucketEncryption(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	listOut, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, wrapErr("listing buckets", err)
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
			return nil, wrapErr(fmt.Sprintf("getting encryption for %s", name), err)
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

func (c *Collector) collectS3PublicAccessBlock(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	listOut, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, wrapErr("listing buckets", err)
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
			return nil, wrapErr(fmt.Sprintf("getting public access block for %s", name), err)
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
