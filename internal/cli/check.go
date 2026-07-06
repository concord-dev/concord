package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/controlpacks"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/pkg/report"
)

func newCheckCmd() *cobra.Command {
	var (
		eval       evalOptions
		format     string
		outputPath string
		push       pushOpts
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Evaluate compliance controls against collected evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := runEvaluation(cmd.Context(), os.Stderr, eval)
			if err != nil {
				return err
			}

			renderer, err := report.RendererFor(format, report.Opts{OrgName: res.orgName})
			if err != nil {
				return err
			}

			out, closeFn, err := openOutput(outputPath)
			if err != nil {
				return err
			}
			defer closeFn()

			summary, err := renderer.Render(out, res.findings)
			if err != nil {
				return fmt.Errorf("rendering: %w", err)
			}

			push.resolveFromCredentials()
			if push.serverURL != "" {
				if err := pushFindings(cmd.Context(), push, res.findings, res.started, res.completed); err != nil {
					fmt.Fprintln(os.Stderr, "push failed:", err)
					os.Exit(1)
				}
				// Heartbeat each live source so the server's evidence-freshness
				// sweep can detect when one goes stale.
				pushEvidenceHeartbeats(cmd.Context(), push, res.liveSources, res.started, res.completed)
				// Assets are secondary to findings: a push failure here warns
				// but doesn't fail the run.
				if len(res.assets) > 0 {
					if err := pushAssets(cmd.Context(), push, res.assets); err != nil {
						fmt.Fprintln(os.Stderr, "asset push failed:", err)
					}
				}
			}

			if summary.Fail > 0 || summary.Err > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
	addEvalFlags(cmd, &eval)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json|oscal|markdown|trust-portal")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write findings to this file (default: stdout)")
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
