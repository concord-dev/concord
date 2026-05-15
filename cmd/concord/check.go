package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/config"
	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/evidence/wiring"
	"github.com/concord-dev/concord/internal/policy"
	"github.com/concord-dev/concord/internal/report"
	"github.com/concord-dev/concord/internal/runner"
)

func newCheckCmd() *cobra.Command {
	var (
		controlsDir  string
		configPath   string
		fixturesOnly bool
		format       string
		outputPath   string
		quiet        bool
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

			loaded, err := controls.Load(controlsDir)
			if err != nil {
				return fmt.Errorf("loading controls: %w", err)
			}
			if len(loaded) == 0 {
				return fmt.Errorf("no controls found in %s", controlsDir)
			}

			reg := wiring.BuildRegistry(context.Background(), fixturesOnly, os.Stderr)
			if !quiet {
				describeMode(os.Stderr, reg, fixturesOnly)
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

			// Optional push to a Concord server. We let pushOpts fall back
			// to the credentials file so `concord login`-only users still
			// trigger a push when --to wasn't supplied. Errors are loud
			// but don't override the non-zero exit below — CI should still
			// fail on a failing audit even when the push itself succeeded.
			push.resolveFromCredentials()
			if push.serverURL != "" {
				if err := pushFindings(cmd.Context(), push, findings, started, completed); err != nil {
					fmt.Fprintln(os.Stderr, "push failed:", err)
					os.Exit(1)
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
	addPushFlags(cmd, &push)
	return cmd
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
