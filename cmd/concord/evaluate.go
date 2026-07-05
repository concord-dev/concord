package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/evidence/wiring"
	"github.com/concord-dev/concord/internal/policy"
	"github.com/concord-dev/concord/internal/runner"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
	"github.com/concord-dev/concord/pkg/config"
	"github.com/concord-dev/concord/pkg/controls"
)

// evalOptions are the inputs shared by every command that evaluates controls
// locally: check (report), plan (diff/gate), and apply (evaluate + record).
// Keeping them in one struct + one flag registrar means the three verbs can
// never drift on how a control set is selected and run.
type evalOptions struct {
	controlsDir  string
	configPath   string
	fixturesOnly bool
	quiet        bool
	frameworks   []string
	severities   []string
	tags         []string
	controlIDs   []string
}

// evalResult is the outcome of one local evaluation. runEvaluation owns the
// whole collector lifecycle (spawn → run → drain → shutdown), so callers get a
// finished result with nothing to defer.
type evalResult struct {
	findings  []apiv1.Finding
	assets    []apiv1.ObservedAsset
	orgName   string
	started   time.Time
	completed time.Time
}

// addEvalFlags registers the control-selection flags common to check/plan/apply.
func addEvalFlags(cmd *cobra.Command, o *evalOptions) {
	cmd.Flags().StringVar(&o.controlsDir, "controls", "./controls", "Path to controls directory")
	cmd.Flags().StringVar(&o.configPath, "config", "./concord.yaml", "Path to concord.yaml")
	cmd.Flags().BoolVar(&o.fixturesOnly, "fixtures", false, "Force fixture-only mode (skip live collectors)")
	cmd.Flags().BoolVarP(&o.quiet, "quiet", "q", false, "Suppress prelude (Mode + Checking lines)")
	cmd.Flags().StringSliceVar(&o.frameworks, "framework", nil, "Only evaluate controls whose metadata.framework matches (repeatable)")
	cmd.Flags().StringSliceVar(&o.severities, "severity", nil, "Only evaluate controls of these severities (repeatable)")
	cmd.Flags().StringSliceVar(&o.tags, "tag", nil, "Only evaluate controls carrying any of these tags (repeatable)")
	cmd.Flags().StringSliceVar(&o.controlIDs, "control-id", nil, "Only evaluate controls with these ids (repeatable)")
}

// runEvaluation loads the config + control set, spins up the collector registry,
// evaluates every matched control, and returns the findings. Progress/prelude
// lines are written to w (unless quiet). Live collector plugins are torn down
// before returning, so the result is self-contained.
func runEvaluation(ctx context.Context, w io.Writer, o evalOptions) (*evalResult, error) {
	cfg, err := config.Load(o.configPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	roots, err := controlRoots(o.controlsDir)
	if err != nil {
		return nil, err
	}
	loaded, err := controls.LoadFrom(roots)
	if err != nil {
		return nil, fmt.Errorf("loading controls: %w", err)
	}
	totalLoaded := len(loaded)
	if totalLoaded == 0 {
		return nil, fmt.Errorf("no controls found in %s or any installed pack", o.controlsDir)
	}
	filter := controls.Filter{
		Frameworks: o.frameworks,
		Severities: o.severities,
		Tags:       o.tags,
		IDs:        o.controlIDs,
	}
	loaded = filter.Apply(loaded)
	if len(loaded) == 0 {
		return nil, fmt.Errorf("filter excluded every control (%d loaded, 0 matched)", totalLoaded)
	}

	built := wiring.BuildRegistry(ctx, wiring.Opts{
		FixturesOnly:  o.fixturesOnly,
		NeededSources: controls.NeededSources(loaded),
		Warn:          w,
	})
	defer built.Shutdown()
	reg := built.Registry
	if !o.quiet {
		describeMode(w, reg, o.fixturesOnly)
		if !filter.Empty() {
			fmt.Fprintf(w, "Filter: %d of %d control(s) matched\n", len(loaded), totalLoaded)
		}
		fmt.Fprintf(w, "Checking %d control(s)...\n\n", len(loaded))
	}

	started := time.Now().UTC()
	r := runner.New(policy.New(), reg).SetParams(cfg.Controls.Params)
	findings := r.RunAll(ctx, loaded)
	completed := time.Now().UTC()

	var assets []apiv1.ObservedAsset
	if built.Manager != nil {
		assets = built.Manager.DrainAssets()
	}

	return &evalResult{
		findings:  findings,
		assets:    assets,
		orgName:   cfg.Metadata.Name,
		started:   started,
		completed: completed,
	}, nil
}
