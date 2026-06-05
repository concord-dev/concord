package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func (c *Collector) collectCloudTrailTrails(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := c.cloudtrail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, wrapErr("describing trails", err)
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
			return nil, wrapErr(fmt.Sprintf("getting status for trail %s", name), err)
		}
		trail["is_logging"] = aws.ToBool(status.IsLogging)
		trails = append(trails, trail)
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"trails":     trails,
	}, nil
}
