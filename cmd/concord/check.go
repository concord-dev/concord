package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/controlpacks"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/evidence/wiring"
	"github.com/concord-dev/concord/internal/policy"
	"github.com/concord-dev/concord/internal/runner"
	"github.com/concord-dev/concord/pkg/config"
	"github.com/concord-dev/concord/pkg/controls"
	"github.com/concord-dev/concord/pkg/report"
)

func newCheckCmd() *cobra.Command {
	var (
		controlsDir  string
		configPath   string
		fixturesOnly bool
		format       string
		outputPath   string
		quiet        bool
		frameworks   []string
		severities   []string
		tags         []string
		controlIDs   []string
		push         pushOpts
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Evaluate compliance controls against collected evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			renderer, err := report.RendererFor(format, report.Opts{OrgName: cfg.Metadata.Name})
			if err != nil {
				return err
			}

			roots, err := controlRoots(controlsDir)
			if err != nil {
				return err
			}
			loaded, err := controls.LoadFrom(roots)
			if err != nil {
				return fmt.Errorf("loading controls: %w", err)
			}
			totalLoaded := len(loaded)
			if totalLoaded == 0 {
				return fmt.Errorf("no controls found in %s or any installed pack", controlsDir)
			}
			filter := controls.Filter{
				Frameworks: frameworks,
				Severities: severities,
				Tags:       tags,
				IDs:        controlIDs,
			}
			loaded = filter.Apply(loaded)
			if len(loaded) == 0 {
				return fmt.Errorf("filter excluded every control (%d loaded, 0 matched)", totalLoaded)
			}

			built := wiring.BuildRegistry(context.Background(), wiring.Opts{
				FixturesOnly:  fixturesOnly,
				NeededSources: controls.NeededSources(loaded),
				Warn:          os.Stderr,
			})
			defer built.Shutdown()
			reg := built.Registry
			if !quiet {
				describeMode(os.Stderr, reg, fixturesOnly)
				if !filter.Empty() {
					fmt.Fprintf(os.Stderr, "Filter: %d of %d control(s) matched\n", len(loaded), totalLoaded)
				}
				fmt.Fprintf(os.Stderr, "Checking %d control(s)...\n\n", len(loaded))
			}

			started := time.Now().UTC()
			r := runner.New(policy.New(), reg).SetParams(cfg.Controls.Params)
			findings := r.RunAll(context.Background(), loaded)
			completed := time.Now().UTC()

			out, closeFn, err := openOutput(outputPath)
			if err != nil {
				return err
			}
			defer closeFn()

			summary, err := renderer.Render(out, findings)
			if err != nil {
				return fmt.Errorf("rendering: %w", err)
			}

			push.resolveFromCredentials()
			if push.serverURL != "" {
				if err := pushFindings(cmd.Context(), push, findings, started, completed); err != nil {
					fmt.Fprintln(os.Stderr, "push failed:", err)
					os.Exit(1)
				}
				// Assets are secondary to findings: a push failure here warns
				// but doesn't fail the run.
				if built.Manager != nil {
					if assets := built.Manager.DrainAssets(); len(assets) > 0 {
						if err := pushAssets(cmd.Context(), push, assets); err != nil {
							fmt.Fprintln(os.Stderr, "asset push failed:", err)
						}
					}
				}
			}

			if summary.Fail > 0 || summary.Err > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&controlsDir, "controls", "./controls", "Path to controls directory")
	cmd.Flags().StringVar(&configPath, "config", "./concord.yaml", "Path to concord.yaml")
	cmd.Flags().BoolVar(&fixturesOnly, "fixtures", false, "Force fixture-only mode (skip live collectors)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json|oscal|markdown|trust-portal")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write findings to this file (default: stdout)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress prelude (Mode + Checking lines)")
	cmd.Flags().StringSliceVar(&frameworks, "framework", nil, "Only evaluate controls whose metadata.framework matches (repeatable)")
	cmd.Flags().StringSliceVar(&severities, "severity", nil, "Only evaluate controls of these severities (repeatable)")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "Only evaluate controls carrying any of these tags (repeatable)")
	cmd.Flags().StringSliceVar(&controlIDs, "control-id", nil, "Only evaluate controls with these ids (repeatable)")
	addPushFlags(cmd, &push)
	return cmd
}

// controlRoots returns the on-disk directories controls.LoadFrom should walk:
// the user's --controls dir (when present) plus every installed control pack.
func controlRoots(controlsDir string) ([]string, error) {
	var roots []string
	if controlsDir != "" {
		if info, err := os.Stat(controlsDir); err == nil && info.IsDir() {
			roots = append(roots, controlsDir)
		}
	}
	discovered, err := controlpacks.Discover("")
	if err != nil {
		return nil, fmt.Errorf("discovering installed control packs: %w", err)
	}
	roots = append(roots, controlpacks.ControlsDirs(discovered)...)
	return roots, nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, fmt.Errorf("creating output dir: %w", err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("creating %s: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

func describeMode(w io.Writer, reg *evidence.Registry, fixturesOnly bool) {
	if fixturesOnly {
		fmt.Fprintln(w, "Mode: fixtures-only")
		return
	}
	sources := reg.Sources()
	if len(sources) == 0 {
		fmt.Fprintln(w, "Mode: live (no live collectors configured — fixtures will be used where declared)")
		return
	}
	fmt.Fprintf(w, "Mode: live · collectors: %v\n", sources)
}
