package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/pkg/report"
)

func newApplyCmd() *cobra.Command {
	var (
		eval         evalOptions
		push         pushOpts
		findingsPath string
		failOnFail   bool
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Evaluate controls and record the run to a Concord server",
		Long: `apply evaluates your controls and records the resulting run to a Concord
server — the compliance equivalent of "terraform apply". Run it on your main
branch (post-merge) to keep the server's recorded posture in sync with the
controls in Git.

apply records the run and, by default, exits 0 even when some controls fail — a
failing control is posture to record, not an apply error. Use "concord plan" to
gate a change before it lands, or pass --fail-on-fail to exit non-zero here too.

apply requires a server target (--to / CONCORD_SERVER_URL / "concord login").
With --findings it records a pre-computed findings file instead of
re-evaluating, which is handy when an earlier CI step already ran the check.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolve + validate the server target before doing the expensive
			// evaluation, so a misconfigured target fails fast.
			push.resolveFromCredentials()
			if err := push.validate(); err != nil {
				return err
			}

			res, err := applyFindings(cmd.Context(), findingsPath, eval)
			if err != nil {
				return err
			}

			if err := pushFindings(cmd.Context(), push, res.findings, res.started, res.completed); err != nil {
				return err
			}
			// Heartbeat each live source so the server's evidence-freshness sweep
			// can detect when one goes stale.
			pushEvidenceHeartbeats(cmd.Context(), push, res.liveSources, res.started, res.completed)
			// Assets are secondary: a push failure warns but doesn't fail apply.
			if len(res.assets) > 0 {
				if err := pushAssets(cmd.Context(), push, res.assets); err != nil {
					fmt.Fprintln(os.Stderr, "asset push failed:", err)
				}
			}

			summary := report.Summarize(res.findings)
			if failOnFail && (summary.Fail > 0 || summary.Err > 0) {
				fmt.Fprintf(os.Stderr, "✗ %d failing / %d errored control(s) (--fail-on-fail)\n",
					summary.Fail, summary.Err)
				os.Exit(1)
			}
			return nil
		},
	}
	addEvalFlags(cmd, &eval)
	cmd.Flags().StringVar(&findingsPath, "findings", "", "Record this pre-computed findings JSON instead of evaluating locally")
	cmd.Flags().BoolVar(&failOnFail, "fail-on-fail", false, "Exit 1 if any recorded control fails or errors (default: exit 0 once recorded)")
	addPushFlags(cmd, &push)
	return cmd
}

// applyFindings produces what apply will record: either a pre-computed file
// (--findings) or a fresh local evaluation. For a pre-computed file the
// timestamps collapse to now and there are no live sources to heartbeat.
func applyFindings(ctx context.Context, findingsPath string, eval evalOptions) (*evalResult, error) {
	if findingsPath != "" {
		f, err := loadFindings(findingsPath)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", findingsPath, err)
		}
		now := time.Now().UTC()
		return &evalResult{findings: f, started: now, completed: now}, nil
	}
	return runEvaluation(ctx, os.Stderr, eval)
}
