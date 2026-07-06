package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/pkg/report"
)

// newGateCmd is the CI entry point: evaluate controls, optionally emit a SARIF
// report for GitHub code scanning, and exit non-zero when any control fails so
// the pipeline blocks the change. It bundles evaluate + SARIF + gate into one
// command so a CI step (or the Concord GitHub Action) is a one-liner
// (assessment/29 P2-A, the adoption wedge).
func newGateCmd() *cobra.Command {
	var (
		eval          evalOptions
		sarifPath     string
		sarifLocation string
		warnAsError   bool
	)
	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Evaluate controls and fail CI on any failing control (optionally emit SARIF)",
		Long: `gate is the CI convenience verb. It evaluates your controls, prints a concise
pass/fail summary, optionally writes a SARIF report for GitHub code scanning
(--sarif), and exits non-zero when any control fails or errors so a pipeline
blocks the change. Pair it with the Concord GitHub Action to annotate PRs.

Summary + status go to stderr; --sarif writes the machine-readable report so
stdout stays free for piping.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := runEvaluation(cmd.Context(), os.Stderr, eval)
			if err != nil {
				return err
			}
			if sarifPath != "" {
				if err := writeSARIFFile(sarifPath, sarifLocation, res); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "wrote SARIF report to %s\n", sarifPath)
			}
			s := report.Summarize(res.findings)
			fmt.Fprintf(os.Stderr, "%d passed · %d failed · %d errored · %d warnings\n", s.Pass, s.Fail, s.Err, s.Warn)
			if s.Fail > 0 || s.Err > 0 || (warnAsError && s.Warn > 0) {
				fmt.Fprintln(os.Stderr, "gate: FAILED — blocking the change")
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "gate: PASSED")
			return nil
		},
	}
	addEvalFlags(cmd, &eval)
	cmd.Flags().StringVar(&sarifPath, "sarif", "", "Write a SARIF report to this file (upload to GitHub code scanning)")
	cmd.Flags().StringVar(&sarifLocation, "sarif-location", "", "Repo file SARIF results point at for PR annotations (default: concord.yaml)")
	cmd.Flags().BoolVar(&warnAsError, "warn-as-error", false, "Also fail the gate when a control emits warnings")
	return cmd
}

// writeSARIFFile renders the findings as SARIF into path.
func writeSARIFFile(path, locationURI string, res *evalResult) error {
	renderer, err := report.RendererFor("sarif", report.Opts{OrgName: res.orgName, SARIFLocationURI: locationURI})
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating SARIF file: %w", err)
	}
	defer f.Close()
	if _, err := renderer.Render(f, res.findings); err != nil {
		return fmt.Errorf("rendering SARIF: %w", err)
	}
	return nil
}
