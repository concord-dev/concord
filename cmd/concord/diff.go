package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/watcher"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func newDiffCmd() *cobra.Command {
	var (
		format      string
		exitOnDrift bool
	)
	cmd := &cobra.Command{
		Use:   "diff <baseline.json> <current.json>",
		Short: "Compare two concord findings files and report drift",
		Long: `diff loads two findings files (as produced by ` + "`concord check --format=json`" + ` or
` + "`concord watch`'s last-run.json) and prints a drift report grouped by regressions," + `
remediations, additions, and removals.

Pipe one branch's findings, then another, then drop the output into a PR
comment to surface compliance drift inline with the change review.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			baseline, err := loadFindings(args[0])
			if err != nil {
				return fmt.Errorf("loading baseline %s: %w", args[0], err)
			}
			current, err := loadFindings(args[1])
			if err != nil {
				return fmt.Errorf("loading current %s: %w", args[1], err)
			}

			events := watcher.Diff(baseline, current, time.Now().UTC())

			switch format {
			case "markdown", "md", "":
				renderDiffMarkdown(os.Stdout, args[0], args[1], baseline, current, events)
			case "json":
				if err := json.NewEncoder(os.Stdout).Encode(events); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown format %q (want markdown|md|json)", format)
			}

			if exitOnDrift && hasRegression(events) {
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "markdown", "Output format: markdown|md|json")
	cmd.Flags().BoolVar(&exitOnDrift, "exit-on-regression", true, "Exit with code 2 if any control regressed (use --exit-on-regression=false to suppress)")
	return cmd
}

func loadFindings(path string) ([]apiv1.Finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var direct []apiv1.Finding
	if err := json.Unmarshal(raw, &direct); err == nil && direct != nil {
		return direct, nil
	}
	var envelope struct {
		Findings []apiv1.Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return envelope.Findings, nil
}

func hasRegression(events []watcher.Event) bool {
	for _, e := range events {
		if e.Reason == "regression" || e.Reason == "evaluation error" {
			return true
		}
	}
	return false
}

func renderDiffMarkdown(w io.Writer, baselinePath, currentPath string, baseline, current []apiv1.Finding, events []watcher.Event) {
	var regressions, remediated, added, removed []watcher.Event
	for _, e := range events {
		switch e.Reason {
		case "regression", "evaluation error":
			regressions = append(regressions, e)
		case "remediated", "evaluation recovered":
			remediated = append(remediated, e)
		default:
			if e.From == "" {
				added = append(added, e)
			} else if string(e.To) == "removed" {
				removed = append(removed, e)
			}
		}
	}

	fmt.Fprintln(w, "# Concord drift report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Baseline**: `%s` (%d controls)  \n", baselinePath, len(baseline))
	fmt.Fprintf(w, "**Current**: `%s` (%d controls)\n\n", currentPath, len(current))

	if len(regressions) == 0 && len(remediated) == 0 && len(added) == 0 && len(removed) == 0 {
		fmt.Fprintln(w, "_No drift — every control's status is unchanged._")
		return
	}

	renderEventTable(w, "🚨 Regressions", regressions, true)
	renderEventTable(w, "✅ Remediated", remediated, true)
	renderEventTable(w, "➕ Added controls", added, false)
	renderEventTable(w, "➖ Removed controls", removed, false)

	unchanged := len(current) - len(regressions) - len(remediated) - len(added)
	if unchanged < 0 {
		unchanged = 0
	}
	fmt.Fprintf(w, "**Unchanged**: %d control(s)\n", unchanged)
}

func renderEventTable(w io.Writer, heading string, events []watcher.Event, withFrom bool) {
	if len(events) == 0 {
		return
	}
	fmt.Fprintf(w, "## %s (%d)\n\n", heading, len(events))
	if withFrom {
		fmt.Fprintln(w, "| Control | Title | Change |")
		fmt.Fprintln(w, "|---|---|---|")
		for _, e := range events {
			fmt.Fprintf(w, "| `%s` | %s | `%s` → `%s` |\n", e.ControlID, mdEscape(e.Title), e.From, e.To)
		}
	} else {
		fmt.Fprintln(w, "| Control | Title | Status |")
		fmt.Fprintln(w, "|---|---|---|")
		for _, e := range events {
			fmt.Fprintf(w, "| `%s` | %s | `%s` |\n", e.ControlID, mdEscape(e.Title), e.To)
		}
	}
	fmt.Fprintln(w)
}

func mdEscape(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '|':
			out = append(out, '\\', '|')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
