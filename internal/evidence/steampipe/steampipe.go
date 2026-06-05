package steampipe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const (
	defaultBinary  = "steampipe"
	defaultTimeout = 90 * time.Second
)

// Config tunes the Steampipe binary invocation. Zero fields fall back to defaults.
type Config struct {
	Binary    string
	Workspace string
	Timeout   time.Duration
	ExtraArgs []string
}

// Collector adapts the Steampipe CLI (single binary, 140+ plugins) to evidence.Collector.
type Collector struct {
	cfg     Config
	runner  runner
}

// runner is the seam tests inject to bypass exec.Command.
type runner func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)

// New returns a Collector that shells out to the local steampipe binary.
func New(cfg Config) *Collector {
	if cfg.Binary == "" {
		cfg.Binary = defaultBinary
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	return &Collector{cfg: cfg, runner: execRunner}
}

// Probe verifies the binary is on PATH and reachable.
func (c *Collector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stdout, stderr, err := c.runner(ctx, c.cfg.Binary, "--version")
	if err != nil {
		return "", fmt.Errorf("steampipe binary not runnable: %w (stderr: %s)", err, strings.TrimSpace(string(stderr)))
	}
	return strings.TrimSpace(string(stdout)), nil
}

// Collect honours one EvidenceRef with source=steampipe. The ref's params
// must include "query" (string). Returns the rows as []map[string]any.
//
// Supported ref.Params keys:
//
//	query     (string, required)  — SQL to execute
//	workspace (string, optional)  — overrides cfg.Workspace
//	timeout   (string, optional)  — Go duration; overrides cfg.Timeout
func (c *Collector) Collect(_ evidence.Context, ref apiv1.EvidenceRef) (any, error) {
	query, _ := ref.Params["query"].(string)
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("%w: steampipe collector requires params.query", evidence.ErrUnsupportedType)
	}

	timeout := c.cfg.Timeout
	if v, ok := ref.Params["timeout"].(string); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}
	workspace := c.cfg.Workspace
	if v, ok := ref.Params["workspace"].(string); ok && v != "" {
		workspace = v
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{"query", "--output", "json"}
	if workspace != "" {
		args = append(args, "--workspace", workspace)
	}
	args = append(args, c.cfg.ExtraArgs...)
	args = append(args, query)

	stdout, stderr, err := c.runner(ctx, c.cfg.Binary, args...)
	if err != nil {
		return nil, fmt.Errorf("steampipe query failed: %w (stderr: %s)", err, truncate(stderr, 4096))
	}

	rows, err := parseRows(stdout)
	if err != nil {
		return nil, fmt.Errorf("parsing steampipe output: %w", err)
	}

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"query":      query,
		"row_count":  len(rows),
		"rows":       rows,
	}, nil
}

// parseRows accepts Steampipe's JSON output. Steampipe writes a JSON array
// of row objects to stdout when --output json is set. Some plugin versions
// emit a {"rows": [...]} envelope; we accept either shape.
func parseRows(raw []byte) ([]map[string]any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return []map[string]any{}, nil
	}
	if trimmed[0] == '[' {
		var rows []map[string]any
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return nil, err
		}
		return rows, nil
	}
	if trimmed[0] == '{' {
		var envelope struct {
			Rows []map[string]any `json:"rows"`
		}
		if err := json.Unmarshal(trimmed, &envelope); err == nil && envelope.Rows != nil {
			return envelope.Rows, nil
		}
		var row map[string]any
		if err := json.Unmarshal(trimmed, &row); err == nil {
			return []map[string]any{row}, nil
		}
	}
	return nil, errors.New("steampipe output is neither a JSON array nor a {rows: [...]} envelope")
}

func execRunner(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
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
