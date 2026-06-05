package prowler

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func TestCollectFromFile_ParsesASFFFixture(t *testing.T) {
	c := New(Config{})
	out, err := c.CollectFromFile("testdata/asff-gdpr-sample.json")
	require.NoError(t, err)
	m := out.(map[string]any)

	assert.EqualValues(t, 3, m["finding_count"])
	assert.EqualValues(t, 2, m["pass_count"])
	assert.EqualValues(t, 1, m["fail_count"])

	findings := m["findings"].([]Finding)
	require.Len(t, findings, 3)

	s3 := findFinding(t, findings, "prowler-s3_bucket_public_access")
	assert.Equal(t, "FAIL", s3.Status)
	assert.Equal(t, "high", s3.Severity)
	assert.Equal(t, "arn:aws:s3:::public-data", s3.ResourceARN)
	assert.Equal(t, "eu-west-1", s3.Region)
	assert.Contains(t, s3.Compliance, "gdpr_eu")
	assert.Contains(t, s3.Compliance, "cis_3.0_aws")
	assert.NotEmpty(t, s3.Remediation)

	rds := findFinding(t, findings, "prowler-rds_instance_storage_encrypted")
	assert.Equal(t, "PASS", rds.Status)
	assert.Equal(t, "informational", rds.Severity)
}

func TestCollect_BinaryInvokedWithCorrectFlags(t *testing.T) {
	var captured []string
	fixtureDir := t.TempDir()
	require.NoError(t, copyFixture("testdata/asff-gdpr-sample.json", filepath.Join(fixtureDir, "out.json")))

	c := New(Config{})
	c.runner = func(_ context.Context, _, _ string, args ...string) ([]byte, []byte, error) {
		captured = args
		return nil, nil, nil
	}
	c.tempDir = func() (string, func(), error) { return fixtureDir, func() {}, nil }

	out, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "prowler",
		Params: map[string]any{
			"provider":   "aws",
			"compliance": "gdpr_eu",
			"services":   []any{"s3", "rds"},
			"regions":    []any{"eu-west-1", "us-east-1"},
		},
	})
	require.NoError(t, err)

	joined := strings.Join(captured, " ")
	assert.Contains(t, joined, "aws")
	assert.Contains(t, joined, "--output-formats json-asff")
	assert.Contains(t, joined, "--compliance gdpr_eu")
	assert.Contains(t, joined, "--services s3 rds")
	assert.Contains(t, joined, "--region eu-west-1 us-east-1")
	assert.Contains(t, joined, "--no-banner")

	m := out.(map[string]any)
	assert.EqualValues(t, 3, m["finding_count"])
}

func TestCollect_NonZeroExitWithFindingsIsTreatedAsSuccess(t *testing.T) {
	fixtureDir := t.TempDir()
	require.NoError(t, copyFixture("testdata/asff-gdpr-sample.json", filepath.Join(fixtureDir, "out.json")))

	c := New(Config{})
	c.runner = func(context.Context, string, string, ...string) ([]byte, []byte, error) {
		return nil, []byte("Findings detected (exit 3)"), errors.New("exit status 3")
	}
	c.tempDir = func() (string, func(), error) { return fixtureDir, func() {}, nil }

	out, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "prowler",
		Params: map[string]any{"provider": "aws"},
	})
	require.NoError(t, err, "non-zero exit with output present must NOT propagate")
	assert.EqualValues(t, 3, out.(map[string]any)["finding_count"])
}

func TestCollect_NonZeroExitWithoutOutputPropagates(t *testing.T) {
	fixtureDir := t.TempDir()

	c := New(Config{})
	c.runner = func(context.Context, string, string, ...string) ([]byte, []byte, error) {
		return nil, []byte("Error: AWS credentials missing"), errors.New("exit status 1")
	}
	c.tempDir = func() (string, func(), error) { return fixtureDir, func() {}, nil }

	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "prowler",
		Params: map[string]any{"provider": "aws"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AWS credentials missing")
}

func TestCollect_ProviderRequired(t *testing.T) {
	c := New(Config{})
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "prowler"})
	require.Error(t, err)
	assert.ErrorIs(t, err, evidence.ErrUnsupportedType)
}

func TestCollect_UnknownProviderRejected(t *testing.T) {
	c := New(Config{})
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "prowler",
		Params: map[string]any{"provider": "vmware"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported provider")
}

func TestParseASFF_AcceptsBareArray(t *testing.T) {
	raw := []byte(`[{"Id":"x","GeneratorId":"g","Compliance":{"Status":"FAILED"},"Severity":{"Label":"LOW"},"Resources":[{"Id":"r"}]}]`)
	findings, err := parseASFF(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "FAIL", findings[0].Status)
	assert.Equal(t, "low", findings[0].Severity)
}

func TestParseASFF_RejectsGarbage(t *testing.T) {
	_, err := parseASFF([]byte("not json"))
	require.Error(t, err)
}

func TestParseASFF_EmptyInputReturnsNil(t *testing.T) {
	out, err := parseASFF([]byte(""))
	require.NoError(t, err)
	assert.Nil(t, out)
}

func findFinding(t *testing.T, fs []Finding, checkID string) Finding {
	t.Helper()
	for _, f := range fs {
		if f.CheckID == checkID {
			return f
		}
	}
	t.Fatalf("check %q not found in findings", checkID)
	return Finding{}
}

func copyFixture(src, dst string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// sanity — parse it through json so we know the test fixture is valid
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	return os.WriteFile(dst, raw, 0644)
}
