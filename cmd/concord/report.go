package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type reportDTO struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Format string `json:"format"`
}

type reportRunDTO struct {
	ID         string     `json:"id"`
	Status     string     `json:"status"`
	Format     string     `json:"format"`
	ByteSize   int        `json:"byte_size"`
	Error      string     `json:"error,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

func reportBase(fs findingsServer) string { return "/v1/orgs/" + fs.orgSlug + "/reports" }

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "report",
		Aliases: []string{"rpt"},
		Short:   "Define and generate compliance reports",
	}
	cmd.AddCommand(newReportCreateCmd())
	cmd.AddCommand(newReportListCmd())
	cmd.AddCommand(newReportShowCmd())
	cmd.AddCommand(newReportDeleteCmd())
	cmd.AddCommand(newReportRunCmd())
	cmd.AddCommand(newReportRunsCmd())
	cmd.AddCommand(newReportDownloadCmd())
	return cmd
}

func newReportCreateCmd() *cobra.Command {
	var serverURL, orgSlug, token, name, kind, format, paramsJSON string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a report definition (kinds: framework_readiness, findings_summary, risk_exposure, annex_iv)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			payload := map[string]any{"name": name, "kind": kind}
			if format != "" {
				payload["format"] = format
			}
			if paramsJSON != "" {
				var p map[string]any
				if err := json.Unmarshal([]byte(paramsJSON), &p); err != nil {
					return fmt.Errorf("--params must be a JSON object: %w", err)
				}
				payload["params"] = p
			}
			var rpt reportDTO
			if err := apiSend(cmd.Context(), fs, "POST", reportBase(fs), payload, &rpt); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s, %s)\n", rpt.ID, rpt.Name, rpt.Kind, rpt.Format)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&name, "name", "", "Report name (required)")
	cmd.Flags().StringVar(&kind, "kind", "", "Report kind (required)")
	cmd.Flags().StringVar(&format, "format", "", "Output format: json|csv|markdown|pdf (default json)")
	cmd.Flags().StringVar(&paramsJSON, "params", "", "Report parameters as a JSON object")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("kind")
	return cmd
}

func newReportListCmd() *cobra.Command {
	var serverURL, orgSlug, token, kind, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List report definitions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			if kind != "" {
				q.Set("kind", kind)
			}
			path := reportBase(fs)
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var rows []reportDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no reports")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tKIND\tFORMAT\tNAME")
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Kind, r.Format, r.Name)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&kind, "kind", "", "Filter by kind")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newReportShowCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one report definition",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var rpt reportDTO
			if err := apiGet(cmd.Context(), fs, reportBase(fs)+"/"+args[0], &rpt); err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(rpt)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newReportDeleteCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a report definition",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if err := apiSend(cmd.Context(), fs, "DELETE", reportBase(fs)+"/"+args[0], nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "deleted %s\n", args[0])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newReportRunCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "run <id>",
		Short: "Generate the report now",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var run reportRunDTO
			if err := apiSend(cmd.Context(), fs, "POST", reportBase(fs)+"/"+args[0]+"/run", nil, &run); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "run %s: %s (%d bytes)", run.ID, run.Status, run.ByteSize)
			if run.Error != "" {
				fmt.Fprintf(os.Stdout, " — %s", run.Error)
			}
			fmt.Fprintln(os.Stdout)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newReportRunsCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "runs <id>",
		Short: "List a report's generation history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var rows []reportRunDTO
			if err := apiGet(cmd.Context(), fs, reportBase(fs)+"/"+args[0]+"/runs", &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no runs")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "RUN\tSTATUS\tBYTES\tFINISHED")
			for _, r := range rows {
				fin := "-"
				if r.FinishedAt != nil {
					fin = r.FinishedAt.Format(time.RFC3339)
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", r.ID, r.Status, r.ByteSize, fin)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newReportDownloadCmd() *cobra.Command {
	var serverURL, orgSlug, token, out string
	cmd := &cobra.Command{
		Use:   "download <id> <run-id>",
		Short: "Download a succeeded run's artifact (use --out for PDF and other binary formats)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			path := reportBase(fs) + "/" + args[0] + "/runs/" + args[1] + "/download"
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, strings.TrimRight(fs.url, "/")+path, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+fs.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			// --out writes the raw bytes to a file — the safe path for a binary
			// (PDF) artifact, which would corrupt a terminal on stdout.
			if out != "" {
				if err := os.WriteFile(out, body, 0o644); err != nil {
					return fmt.Errorf("writing %s: %w", out, err)
				}
				fmt.Fprintf(os.Stderr, "✓ wrote %d bytes to %s\n", len(body), out)
				return nil
			}
			_, err = os.Stdout.Write(body)
			return err
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&out, "out", "", "Write the artifact to this file instead of stdout (use for PDF)")
	return cmd
}
