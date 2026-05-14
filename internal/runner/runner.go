// Package runner executes a set of controls against an evidence collector.
package runner

import (
	"context"
	"path/filepath"
	"time"

	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/policy"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Runner evaluates controls and produces findings.
type Runner struct {
	engine    *policy.Engine
	collector evidence.Collector
	params    map[string]map[string]any
}

// New constructs a Runner.
func New(engine *policy.Engine, collector evidence.Collector) *Runner {
	return &Runner{engine: engine, collector: collector}
}

// SetParams installs a per-control parameter override map. Each control's
// params (keyed by control ID) are exposed to Rego at input._concord.params.
func (r *Runner) SetParams(p map[string]map[string]any) *Runner {
	r.params = p
	return r
}

// Run evaluates a single control and returns its finding.
func (r *Runner) Run(ctx context.Context, loaded controls.Loaded) apiv1.Finding {
	start := time.Now()
	c := loaded.Control
	f := apiv1.Finding{
		ControlID:   c.Metadata.ID,
		Title:       c.Metadata.Title,
		Framework:   c.Metadata.Framework,
		Severity:    c.Metadata.Severity,
		Mappings:    c.Spec.Mappings,
		EvaluatedAt: start.UTC(),
	}

	controlDir := filepath.Dir(loaded.Path)

	input, err := evidence.CollectAll(r.collector, evidence.Context{ControlDir: controlDir}, c.Spec.Evidence)
	if err != nil {
		f.Status = apiv1.StatusError
		f.Messages = []string{"evidence: " + err.Error()}
		f.DurationMs = time.Since(start).Milliseconds()
		return f
	}

	params := map[string]any{}
	if r.params != nil {
		if p, ok := r.params[c.Metadata.ID]; ok {
			for k, v := range p {
				params[k] = v
			}
		}
	}
	input["_concord"] = map[string]any{"params": params}

	regoPath := c.Spec.Policy.File
	if !filepath.IsAbs(regoPath) {
		regoPath = filepath.Join(controlDir, regoPath)
	}
	res, err := r.engine.EvaluateFile(ctx, regoPath, c.Spec.Policy.Package, input)
	if err != nil {
		f.Status = apiv1.StatusError
		f.Messages = []string{"policy: " + err.Error()}
		f.DurationMs = time.Since(start).Milliseconds()
		return f
	}

	f.Warnings = res.Warn
	if res.Pass {
		f.Status = apiv1.StatusPass
	} else {
		f.Status = apiv1.StatusFail
		f.Messages = res.Deny
	}
	f.DurationMs = time.Since(start).Milliseconds()
	return f
}

// RunAll evaluates every loaded control and returns findings in input order.
func (r *Runner) RunAll(ctx context.Context, loaded []controls.Loaded) []apiv1.Finding {
	out := make([]apiv1.Finding, 0, len(loaded))
	for _, l := range loaded {
		out = append(out, r.Run(ctx, l))
	}
	return out
}
