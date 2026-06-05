package prowler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const (
	defaultBinary  = "prowler"
	defaultTimeout = 30 * time.Minute
)

// Config tunes how the Prowler binary is invoked. Zero fields fall back to defaults.
type Config struct {
	Binary  string
	Timeout time.Duration
	WorkDir string
}

// Collector adapts the Prowler scanner (AWS/GCP/Azure/K8s, GDPR/HIPAA/PCI/CIS/NIST/ISO/SOC2 mappings) to evidence.Collector.
type Collector struct {
	cfg    Config
	runner runner
	readFile func(string) ([]byte, error)
	tempDir func() (string, func(), error)
}

type runner func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, error)

// New returns a Collector that shells out to the local prowler binary.
func New(cfg Config) *Collector {
	if cfg.Binary == "" {
		cfg.Binary = defaultBinary
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	return &Collector{
		cfg:      cfg,
		runner:   execRunner,
		readFile: os.ReadFile,
		tempDir:  defaultTempDir,
	}
}

// Probe checks the binary is runnable.
func (c *Collector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stdout, stderr, err := c.runner(ctx, c.cfg.WorkDir, c.cfg.Binary, "--version")
	if err != nil {
		return "", fmt.Errorf("prowler binary not runnable: %w (stderr: %s)", err, strings.TrimSpace(string(stderr)))
	}
	return strings.TrimSpace(string(stdout)), nil
}

// Collect runs Prowler once and returns its parsed findings.
//
// Required params:
//
//	provider   (string) — aws | gcp | azure | kubernetes
//
// Optional params:
//
//	compliance (string|[]string) — one or more compliance frameworks
//	                               (e.g. "gdpr_eu", "hipaa", "cis_3.0_aws")
//	services   ([]string)        — restrict to these services
//	checks     ([]string)        — restrict to these check IDs
//	regions    ([]string)        — AWS regions to scan
//	severity   (string|[]string) — restrict by severity (critical|high|medium|low|informational)
//	args       ([]string)        — opaque extra args appended verbatim
//	timeout    (string)          — Go duration override
func (c *Collector) Collect(_ evidence.Context, ref apiv1.EvidenceRef) (any, error) {
	provider, _ := ref.Params["provider"].(string)
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return nil, fmt.Errorf("%w: prowler collector requires params.provider (aws|gcp|azure|kubernetes)", evidence.ErrUnsupportedType)
	}
	if !validProvider(provider) {
		return nil, fmt.Errorf("prowler: unsupported provider %q", provider)
	}

	timeout := c.cfg.Timeout
	if v, ok := ref.Params["timeout"].(string); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}

	outDir, cleanup, err := c.tempDir()
	if err != nil {
		return nil, fmt.Errorf("prowler: tempdir: %w", err)
	}
	defer cleanup()

	args := []string{
		provider,
		"--output-formats", "json-asff",
		"--output-directory", outDir,
		"--no-banner",
	}
	if compliance := stringOrList(ref.Params["compliance"]); len(compliance) > 0 {
		args = append(args, "--compliance")
		args = append(args, compliance...)
	}
	if services := stringOrList(ref.Params["services"]); len(services) > 0 {
		args = append(args, "--services")
		args = append(args, services...)
	}
	if checks := stringOrList(ref.Params["checks"]); len(checks) > 0 {
		args = append(args, "--checks")
		args = append(args, checks...)
	}
	if regions := stringOrList(ref.Params["regions"]); len(regions) > 0 {
		args = append(args, "--region")
		args = append(args, regions...)
	}
	if severity := stringOrList(ref.Params["severity"]); len(severity) > 0 {
		args = append(args, "--severity")
		args = append(args, severity...)
	}
	if extra := stringOrList(ref.Params["args"]); len(extra) > 0 {
		args = append(args, extra...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, stderr, err := c.runner(ctx, c.cfg.WorkDir, c.cfg.Binary, args...)
	if err != nil {
		// Prowler returns non-zero when any check fails — that's expected,
		// not a scanner-level error. We rely on the output file existing
		// to distinguish "scanner crashed" from "checks reported failures".
		if findings, parseErr := c.readFindings(outDir); parseErr == nil && len(findings) > 0 {
			return summarise(findings, provider, ref.Params), nil
		}
		return nil, fmt.Errorf("prowler run failed: %w (stderr: %s)", err, truncate(stderr, 4096))
	}

	findings, err := c.readFindings(outDir)
	if err != nil {
		return nil, fmt.Errorf("parsing prowler output: %w", err)
	}
	return summarise(findings, provider, ref.Params), nil
}

// CollectFromFile is the test-only path: parse a pre-recorded ASFF JSON
// file as if Prowler had just produced it. Lets unit tests + fixtures
// drive the same code path without invoking the binary.
func (c *Collector) CollectFromFile(path string) (any, error) {
	raw, err := c.readFile(path)
	if err != nil {
		return nil, err
	}
	findings, err := parseASFF(raw)
	if err != nil {
		return nil, err
	}
	return summarise(findings, "fixture", nil), nil
}

// findings + summary types — public so Rego policies have a stable shape.

// Finding is one Prowler check result, normalised to Concord's shape.
type Finding struct {
	CheckID       string            `json:"check_id"`
	Title         string            `json:"title"`
	Provider      string            `json:"provider"`
	Service       string            `json:"service"`
	Region        string            `json:"region"`
	ResourceARN   string            `json:"resource_arn,omitempty"`
	ResourceID    string            `json:"resource_id,omitempty"`
	AccountID     string            `json:"account_id,omitempty"`
	Status        string            `json:"status"` // "PASS" | "FAIL" | "MANUAL"
	StatusExtended string           `json:"status_extended,omitempty"`
	Severity      string            `json:"severity"`
	Compliance    map[string][]string `json:"compliance,omitempty"`
	Description   string            `json:"description,omitempty"`
	Remediation   string            `json:"remediation,omitempty"`
}

func summarise(findings []Finding, provider string, params map[string]any) map[string]any {
	pass, fail, manual := 0, 0, 0
	byCheck := map[string]int{}
	bySeverity := map[string]int{}
	for _, f := range findings {
		switch f.Status {
		case "PASS":
			pass++
		case "FAIL":
			fail++
			byCheck[f.CheckID]++
			bySeverity[strings.ToLower(f.Severity)]++
		case "MANUAL":
			manual++
		}
	}
	return map[string]any{
		"fetched_at":      time.Now().UTC().Format(time.RFC3339),
		"provider":        provider,
		"params":          params,
		"finding_count":   len(findings),
		"pass_count":      pass,
		"fail_count":      fail,
		"manual_count":    manual,
		"failures_by_check":    byCheck,
		"failures_by_severity": bySeverity,
		"findings":        findings,
	}
}

func (c *Collector) readFindings(dir string) ([]Finding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading prowler output dir %s: %w", dir, err)
	}
	var all []Finding
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".asff.json") {
			continue
		}
		raw, err := c.readFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		fs, err := parseASFF(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", e.Name(), err)
		}
		all = append(all, fs...)
	}
	return all, nil
}

// asffWire mirrors the subset of AWS Security Finding Format fields
// Prowler emits. We only model what we read; the rest stays opaque.
type asffWire struct {
	Findings []asffFinding `json:"Findings"`
}

type asffFinding struct {
	ID               string                   `json:"Id"`
	GeneratorID      string                   `json:"GeneratorId"`
	AwsAccountID     string                   `json:"AwsAccountId"`
	Title            string                   `json:"Title"`
	Description      string                   `json:"Description"`
	Severity         struct {
		Label string `json:"Label"`
	} `json:"Severity"`
	Compliance struct {
		Status              string   `json:"Status"`
		AssociatedStandards []asffStandard `json:"AssociatedStandards"`
		RelatedRequirements []string `json:"RelatedRequirements"`
	} `json:"Compliance"`
	Resources       []asffResource `json:"Resources"`
	ProductFields   map[string]any `json:"ProductFields"`
	Remediation struct {
		Recommendation struct {
			Text string `json:"Text"`
		} `json:"Recommendation"`
	} `json:"Remediation"`
}

type asffStandard struct {
	StandardsID string `json:"StandardsId"`
}

type asffResource struct {
	ID     string `json:"Id"`
	Type   string `json:"Type"`
	Region string `json:"Region"`
}

func parseASFF(raw []byte) ([]Finding, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []asffFinding
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, err
		}
		return mapASFF(arr), nil
	}
	if trimmed[0] == '{' {
		var w asffWire
		if err := json.Unmarshal(trimmed, &w); err != nil {
			return nil, err
		}
		if len(w.Findings) > 0 {
			return mapASFF(w.Findings), nil
		}
		var one asffFinding
		if err := json.Unmarshal(trimmed, &one); err == nil && one.ID != "" {
			return mapASFF([]asffFinding{one}), nil
		}
	}
	return nil, errors.New("prowler output is not recognised ASFF JSON")
}

func mapASFF(raw []asffFinding) []Finding {
	out := make([]Finding, 0, len(raw))
	for _, f := range raw {
		out = append(out, mapOne(f))
	}
	return out
}

func mapOne(f asffFinding) Finding {
	var resARN, resID, region string
	if len(f.Resources) > 0 {
		resARN = f.Resources[0].ID
		resID = f.Resources[0].ID
		region = f.Resources[0].Region
	}
	compliance := map[string][]string{}
	for _, s := range f.Compliance.AssociatedStandards {
		if s.StandardsID == "" {
			continue
		}
		compliance[s.StandardsID] = append(compliance[s.StandardsID], f.Compliance.RelatedRequirements...)
	}
	if len(compliance) == 0 && len(f.Compliance.RelatedRequirements) > 0 {
		compliance["unspecified"] = f.Compliance.RelatedRequirements
	}
	severity := strings.ToLower(f.Severity.Label)
	if severity == "" {
		severity = "informational"
	}
	status := strings.ToUpper(f.Compliance.Status)
	switch status {
	case "PASSED":
		status = "PASS"
	case "FAILED":
		status = "FAIL"
	case "WARNING":
		status = "MANUAL"
	}
	checkID := f.GeneratorID
	if checkID == "" {
		checkID = f.ID
	}
	service := ""
	if v, ok := f.ProductFields["ProviderName"].(string); ok {
		service = v
	}
	if v, ok := f.ProductFields["Service"].(string); ok {
		service = v
	}
	return Finding{
		CheckID:        checkID,
		Title:          f.Title,
		Provider:       "",
		Service:        service,
		Region:         region,
		ResourceARN:    resARN,
		ResourceID:     resID,
		AccountID:      f.AwsAccountID,
		Status:         status,
		StatusExtended: f.Description,
		Severity:       severity,
		Compliance:     compliance,
		Description:    f.Description,
		Remediation:    f.Remediation.Recommendation.Text,
	}
}

func validProvider(p string) bool {
	switch p {
	case "aws", "gcp", "azure", "kubernetes":
		return true
	}
	return false
}

func stringOrList(v any) []string {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil
		}
		return []string{s}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func defaultTempDir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "concord-prowler-*")
	if err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

func execRunner(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func truncate(b []byte, max int) string {
	s := string(b)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
