package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/watcher"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// planExitRegression mirrors `terraform plan -detailed-exitcode`: a clean plan
// exits 0, an error exits 1 (cobra's default), and a plan that would regress
// posture exits with this distinct code so CI can gate a pull request on it.
const planExitRegression = 2

func newPlanCmd() *cobra.Command {
	var (
		eval        evalOptions
		baseline    string
		current     string
		fromServer  bool
		format      string
		exitOnReg   bool
		srvURL      string
		orgSlug     string
		token       string
		projectSlug string
	)
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Preview compliance drift against a baseline without recording it",
		Long: `plan evaluates your controls and compares the result to a baseline — the
compliance equivalent of "terraform plan". It shows which controls would
regress, recover, appear, or disappear, and by default exits 2 when any control
regresses, so you can gate a pull request in CI before the change lands.

plan never records anything. Use "concord apply" to record a run.

The baseline is chosen in this order:
  --baseline <file>   a findings JSON captured earlier (e.g. from the main branch)
  --from-server       the posture currently recorded on the Concord server
With no baseline every control is reported as newly added (nothing to compare
against) and plan exits 0.

The current posture is evaluated locally, or read from --current <file> when an
earlier step already ran "concord check --format json -o findings.json".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			curr, err := currentFindings(cmd.Context(), current, eval)
			if err != nil {
				return err
			}

			base, label, err := planBaseline(cmd.Context(), baseline, fromServer, srvURL, orgSlug, projectSlug, token)
			if err != nil {
				return err
			}

			events := watcher.Diff(base, curr, time.Now().UTC())

			switch format {
			case "text", "":
				renderPlanText(os.Stdout, curr, events, label, base != nil)
			case "markdown", "md":
				renderDiffMarkdown(os.Stdout, label, "current", base, curr, events)
			case "json":
				if err := json.NewEncoder(os.Stdout).Encode(events); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown format %q (want text|markdown|json)", format)
			}

			if exitOnReg && hasRegression(events) {
				os.Exit(planExitRegression)
			}
			return nil
		},
	}
	addEvalFlags(cmd, &eval)
	cmd.Flags().StringVar(&baseline, "baseline", "", "Baseline findings JSON to compare against (e.g. captured from the main branch)")
	cmd.Flags().StringVar(&current, "current", "", "Use this findings JSON as the current posture instead of evaluating locally")
	cmd.Flags().BoolVar(&fromServer, "from-server", false, "Use the posture recorded on the Concord server as the baseline")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|markdown|json")
	cmd.Flags().BoolVar(&exitOnReg, "exit-on-regression", true, "Exit 2 if any control would regress (use --exit-on-regression=false to always exit 0)")
	// Server flags are only consulted with --from-server.
	addFindingsServerFlags(cmd, &srvURL, &orgSlug, &token)
	addProjectFlag(cmd, &projectSlug)
	return cmd
}

// currentFindings returns the posture to plan against a baseline: either a
// pre-computed findings file (--current) or a fresh local evaluation.
func currentFindings(ctx context.Context, currentPath string, eval evalOptions) ([]apiv1.Finding, error) {
	if currentPath != "" {
		return loadFindings(currentPath)
	}
	res, err := runEvaluation(ctx, os.Stderr, eval)
	if err != nil {
		return nil, err
	}
	return res.findings, nil
}

// planBaseline resolves the baseline posture and a human-readable label for it.
// A nil baseline (no source given) is not an error — plan then reports every
// control as newly added.
func planBaseline(ctx context.Context, path string, fromServer bool, srvURL, orgSlug, projectSlug, token string) ([]apiv1.Finding, string, error) {
	switch {
	case path != "":
		base, err := loadFindings(path)
		if err != nil {
			return nil, "", fmt.Errorf("loading baseline %s: %w", path, err)
		}
		return base, path, nil
	case fromServer:
		fs, err := resolveServer(srvURL, orgSlug, projectSlug, token)
		if err != nil {
			return nil, "", err
		}
		base, err := serverBaseline(ctx, fs)
		if err != nil {
			return nil, "", err
		}
		return base, fs.url + " (recorded posture)", nil
	default:
		return nil, "(no baseline)", nil
	}
}

// serverBaseline fetches the org/project's currently recorded findings and maps
// them to the finding shape the differ compares on. The recorded evaluation
// status (not the lifecycle status) is what drift is measured against.
func serverBaseline(ctx context.Context, fs findingsServer) ([]apiv1.Finding, error) {
	rows, err := getFindings(ctx, fs, nil)
	if err != nil {
		return nil, err
	}
	return mapDTOsToFindings(rows), nil
}

// mapDTOsToFindings converts recorded findings to the shape the differ compares
// on, diffing against the recorded evaluation status (falling back to the
// lifecycle status only when the eval status is absent).
func mapDTOsToFindings(rows []findingDTO) []apiv1.Finding {
	out := make([]apiv1.Finding, 0, len(rows))
	for _, r := range rows {
		status := r.CurrentEvaluationStatus
		if status == "" {
			status = r.Status
		}
		out = append(out, apiv1.Finding{
			ControlID: r.ControlID,
			Framework: r.Framework,
			Severity:  r.Severity,
			Status:    apiv1.FindingStatus(status),
		})
	}
	return out
}

// renderPlanText prints a Terraform-plan-style summary: one aligned line per
// changed control prefixed with a change symbol, then a one-line tally.
func renderPlanText(w io.Writer, current []apiv1.Finding, events []watcher.Event, baselineLabel string, hadBaseline bool) {
	fmt.Fprintf(w, "Concord plan — %d control(s) evaluated against %s\n\n", len(current), baselineLabel)

	if !hadBaseline {
		fmt.Fprintln(w, "No baseline to compare against; every control is reported as new.")
		fmt.Fprintln(w, "Pass --baseline <file> or --from-server to detect drift.")
		fmt.Fprintln(w)
	}

	if len(events) == 0 {
		fmt.Fprintln(w, "No posture changes. Controls match the baseline.")
		return
	}

	var regress, recovered, added, removed, changed int
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	for _, e := range events {
		sym, note := planSymbol(e)
		switch e.Reason {
		case "regression", "evaluation error":
			regress++
		case "remediated", "evaluation recovered":
			recovered++
		default:
			if e.From == "" {
				added++
			} else if string(e.To) == "removed" {
				removed++
			} else {
				changed++
			}
		}
		fmt.Fprintf(tw, "  %s %s\t%s\t%s\n", sym, controlLabel(e.ControlID, e.ResourceID), planTransition(e), note)
	}
	_ = tw.Flush()

	fmt.Fprintf(w, "\nPlan: %d to regress, %d recovered, %d added, %d removed",
		regress, recovered, added, removed)
	if changed > 0 {
		fmt.Fprintf(w, ", %d changed", changed)
	}
	fmt.Fprintln(w, ".")

	if regress > 0 {
		fmt.Fprintf(w, "\n✗ %d control(s) would regress.\n", regress)
	}
}

// planSymbol maps a drift event to a Terraform-like change glyph and label:
// ! regression, ~ recovered/changed, + added, - removed.
func planSymbol(e watcher.Event) (symbol, note string) {
	switch e.Reason {
	case "regression", "evaluation error":
		return "!", e.Reason
	case "remediated", "evaluation recovered":
		return "~", e.Reason
	}
	if e.From == "" {
		return "+", "added"
	}
	if string(e.To) == "removed" {
		return "-", "removed"
	}
	return "~", "changed"
}

func planTransition(e watcher.Event) string {
	if e.From == "" {
		return string(e.To)
	}
	if string(e.To) == "removed" {
		return string(e.From) + " → (removed)"
	}
	return string(e.From) + " → " + string(e.To)
}
