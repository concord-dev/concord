package runner

import (
	"context"
	"path/filepath"
	"time"

	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/policy"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
	"github.com/concord-dev/concord/pkg/controls"
)

type Runner struct {
	engine    *policy.Engine
	collector evidence.Collector
	params    map[string]map[string]any
}

func New(engine *policy.Engine, collector evidence.Collector) *Runner {
	return &Runner{engine: engine, collector: collector}
}

func (r *Runner) SetParams(p map[string]map[string]any) *Runner {
	r.params = p
	return r
}

// Run evaluates one control and returns a single finding. When a policy emits
// per-resource verdicts it returns the first; use RunControl to get them all.
// Kept for callers (and tests) that expect exactly one finding per control.
func (r *Runner) Run(ctx context.Context, loaded controls.Loaded) apiv1.Finding {
	return r.RunControl(ctx, loaded)[0]
}

// RunControl evaluates one control and returns its findings: exactly one
// control-level finding, or — when the policy defines `resource_findings` — one
// finding per resource. It always returns at least one finding (an error
// finding on evidence/policy failure), so callers can index [0] safely.
func (r *Runner) RunControl(ctx context.Context, loaded controls.Loaded) []apiv1.Finding {
	start := time.Now()
	c := loaded.Control
	base := apiv1.Finding{
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
		base.Status = apiv1.StatusError
		base.Messages = []string{"evidence: " + err.Error()}
		base.DurationMs = time.Since(start).Milliseconds()
		return []apiv1.Finding{base}
	}

	// Commit the finding to the exact evidence it was evaluated against, before
	// the runner mixes in synthetic params. The server records this so a pushed
	// finding is tied to verifiable inputs rather than trusted blindly. Every
	// per-resource finding shares the control's evidence digest.
	base.EvidenceFingerprint = apiv1.FingerprintEvidence(input)

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
		base.Status = apiv1.StatusError
		base.Messages = []string{"policy: " + err.Error()}
		base.DurationMs = time.Since(start).Milliseconds()
		return []apiv1.Finding{base}
	}
	base.DurationMs = time.Since(start).Milliseconds()

	// Per-resource mode: one finding per resource verdict replaces the single
	// control-level finding (the aggregate posture is recomputed downstream from
	// the per-resource set).
	if len(res.Resources) > 0 {
		return fanOutResources(base, res.Resources)
	}

	// Control-level: one finding for the whole control.
	f := base
	f.Warnings = res.Warn
	if res.Pass {
		f.Status = apiv1.StatusPass
	} else {
		f.Status = apiv1.StatusFail
		f.Messages = res.Deny
	}
	return []apiv1.Finding{f}
}

// fanOutResources expands per-resource verdicts into one finding each, copying
// the control-level metadata (and shared evidence digest) onto every finding.
func fanOutResources(base apiv1.Finding, verdicts []policy.ResourceVerdict) []apiv1.Finding {
	out := make([]apiv1.Finding, 0, len(verdicts))
	for _, v := range verdicts {
		f := base
		f.ResourceID = v.Resource
		switch v.Status {
		case "pass":
			f.Status = apiv1.StatusPass
		case "warn":
			// A warn resource still passes; surface the reasons as warnings.
			f.Status = apiv1.StatusPass
			f.Warnings = v.Messages
		default: // "fail" or anything unexpected → fail closed
			f.Status = apiv1.StatusFail
			f.Messages = v.Messages
		}
		out = append(out, f)
	}
	return out
}

func (r *Runner) RunAll(ctx context.Context, loaded []controls.Loaded) []apiv1.Finding {
	out := make([]apiv1.Finding, 0, len(loaded))
	for _, l := range loaded {
		out = append(out, r.RunControl(ctx, l)...)
	}
	return out
}
