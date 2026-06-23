package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type runListEntry struct {
	ID           string     `json:"id"`
	Status       string     `json:"status"`
	Source       string     `json:"source"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
	AgentVersion string     `json:"agent_version,omitempty"`
}

type runDetail struct {
	RunID        string         `json:"run_id"`
	Status       string         `json:"status"`
	Source       string         `json:"source"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
	AgentVersion string         `json:"agent_version,omitempty"`
	Summary      map[string]any `json:"summary"`
	Findings     []any          `json:"findings"`
}

func newRunsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "runs",
		Short: "Query the platform's run history",
	}
	cmd.AddCommand(newRunsListCmd())
	cmd.AddCommand(newRunsShowCmd())
	return cmd
}

func newRunsListCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		since                     string
		format                    string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the most recent runs",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			path := fs.projectBase() + "/runs"
			var rows []runListEntry
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if since != "" {
				cutoff, err := parseUntil(since)
				if err != nil {
					return err
				}
				rows = filterRunsSince(rows, cutoff)
			}
			return printRuns(os.Stdout, rows, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&since, "since", "", "Filter to runs started after this time (RFC3339 or 30d / 8w / 6mo)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newRunsShowCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		format                    string
		latest                    bool
	)
	cmd := &cobra.Command{
		Use:   "show [run-id]",
		Short: "Show one run's summary + findings (use --latest to fetch the most recent succeeded run)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			path := ""
			switch {
			case latest:
				path = fs.projectBase() + "/runs/latest"
			case len(args) == 1:
				path = fs.projectBase() + "/runs/" + url.PathEscape(args[0])
			default:
				return fmt.Errorf("provide a run id or pass --latest")
			}
			var run runDetail
			if err := apiGet(cmd.Context(), fs, path, &run); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(run)
			}
			fmt.Fprintf(os.Stdout, "Run      : %s\n", run.RunID)
			fmt.Fprintf(os.Stdout, "Status   : %s (source=%s)\n", run.Status, run.Source)
			fmt.Fprintf(os.Stdout, "Started  : %s\n", run.StartedAt.Format(time.RFC3339))
			if run.CompletedAt != nil {
				fmt.Fprintf(os.Stdout, "Finished : %s\n", run.CompletedAt.Format(time.RFC3339))
			}
			if len(run.Summary) > 0 {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("Summary : ", "          ")
				_ = enc.Encode(run.Summary)
			}
			fmt.Fprintf(os.Stdout, "Findings : %d\n", len(run.Findings))
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().BoolVar(&latest, "latest", false, "Fetch the most recent succeeded run")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func filterRunsSince(rows []runListEntry, cutoff time.Time) []runListEntry {
	out := rows[:0]
	for _, r := range rows {
		if !r.StartedAt.Before(cutoff) {
			out = append(out, r)
		}
	}
	return out
}

func printRuns(w io.Writer, rows []runListEntry, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no runs")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tSOURCE\tSTARTED\tCOMPLETED\tAGENT")
	for _, r := range rows {
		completed := "—"
		if r.CompletedAt != nil {
			completed = r.CompletedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			shortRunID(r.ID), r.Status, r.Source,
			r.StartedAt.Format(time.RFC3339), completed, r.AgentVersion)
	}
	return tw.Flush()
}

func shortRunID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
