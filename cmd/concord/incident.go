package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type incidentDTO struct {
	ID                 string     `json:"id"`
	OrgID              string     `json:"org_id"`
	ProjectID          string     `json:"project_id"`
	Title              string     `json:"title"`
	Summary            string     `json:"summary,omitempty"`
	Severity           string     `json:"severity"`
	Status             string     `json:"status"`
	OpenedAt           time.Time  `json:"opened_at"`
	MitigatedAt        *time.Time `json:"mitigated_at,omitempty"`
	ResolvedAt         *time.Time `json:"resolved_at,omitempty"`
	PostmortemURL      string     `json:"postmortem_url,omitempty"`
	PostmortemMarkdown string     `json:"postmortem_markdown,omitempty"`
	AffectedControls   []string   `json:"affected_controls,omitempty"`
	EscalatedAt        *time.Time `json:"escalated_at,omitempty"`
}

type incidentEventDTO struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	Kind       string    `json:"kind"`
	FromStatus string    `json:"from_status,omitempty"`
	ToStatus   string    `json:"to_status,omitempty"`
	Body       string    `json:"body,omitempty"`
}

func newIncidentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "incident",
		Short: "Open and manage incidents (SOC 2 / ISO 27001 incident response)",
	}
	cmd.AddCommand(newIncidentOpenCmd())
	cmd.AddCommand(newIncidentListCmd())
	cmd.AddCommand(newIncidentShowCmd())
	cmd.AddCommand(newIncidentCommentCmd())
	cmd.AddCommand(newIncidentMitigateCmd())
	cmd.AddCommand(newIncidentResolveCmd())
	cmd.AddCommand(newIncidentPostmortemCmd())
	return cmd
}

func newIncidentOpenCmd() *cobra.Command {
	var (
		serverURL, orgSlug, projectSlug, token string
		title, summary, severity, comment      string
		affectedControls                       []string
	)
	cmd := &cobra.Command{
		Use:   "open",
		Short: "Open a new incident in the project",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(serverURL, orgSlug, projectSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{
				"title":    strings.TrimSpace(title),
				"severity": strings.TrimSpace(severity),
			}
			if summary != "" {
				body["summary"] = summary
			}
			if comment != "" {
				body["comment"] = comment
			}
			if len(affectedControls) > 0 {
				body["affected_controls"] = affectedControls
			}
			var inc incidentDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				fs.projectBase()+"/incidents", body, &inc); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s opened — %s (%s, %s)\n", inc.ID, inc.Title, inc.Severity, inc.Status)
			return nil
		},
	}
	addProjectServerFlags(cmd, &serverURL, &orgSlug, &projectSlug, &token)
	cmd.Flags().StringVar(&title, "title", "", "Short incident name (required)")
	cmd.Flags().StringVar(&summary, "summary", "", "Free-text summary")
	cmd.Flags().StringVar(&severity, "severity", "", "Severity: low|medium|high|critical (required)")
	cmd.Flags().StringVar(&comment, "comment", "", "Initial comment recorded with the open event")
	cmd.Flags().StringSliceVar(&affectedControls, "control", nil, "Affected control id (repeatable, e.g. -c CC7.1)")
	_ = cmd.MarkFlagRequired("title")
	_ = cmd.MarkFlagRequired("severity")
	return cmd
}

func newIncidentListCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token    string
		statusFilter, severityFilter []string
		sinceStr, untilStr, format   string
		allProjects                  bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List incidents (defaults to the active project)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(serverURL, orgSlug, "", token)
			if err != nil {
				return err
			}
			path := fs.projectBase() + "/incidents"
			if allProjects {
				path = "/v1/orgs/" + fs.orgSlug + "/incidents"
			}
			q := url.Values{}
			for _, s := range statusFilter {
				q.Add("status", s)
			}
			for _, s := range severityFilter {
				q.Add("severity", s)
			}
			if sinceStr != "" {
				q.Set("since", sinceStr)
			}
			if untilStr != "" {
				q.Set("until", untilStr)
			}
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var rows []incidentDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			return printIncidents(os.Stdout, rows, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringSliceVar(&statusFilter, "status", nil, "Filter by status (repeatable)")
	cmd.Flags().StringSliceVar(&severityFilter, "severity", nil, "Filter by severity (repeatable)")
	cmd.Flags().StringVar(&sinceStr, "since", "", "List incidents opened on/after this RFC3339 time")
	cmd.Flags().StringVar(&untilStr, "until", "", "List incidents opened before this RFC3339 time")
	cmd.Flags().BoolVar(&allProjects, "all-projects", false, "List across every project in the org")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newIncidentShowCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		format                    string
		showEvents                bool
	)
	cmd := &cobra.Command{
		Use:   "show <incident-id>",
		Short: "Show one incident with its full event log",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var inc incidentDTO
			if err := apiGet(cmd.Context(), fs,
				"/v1/orgs/"+fs.orgSlug+"/incidents/"+args[0], &inc); err != nil {
				return err
			}
			if format == "json" {
				if showEvents {
					var events []incidentEventDTO
					_ = apiGet(cmd.Context(), fs,
						"/v1/orgs/"+fs.orgSlug+"/incidents/"+args[0]+"/events", &events)
					return json.NewEncoder(os.Stdout).Encode(map[string]any{
						"incident": inc,
						"events":   events,
					})
				}
				return json.NewEncoder(os.Stdout).Encode(inc)
			}
			printOneIncident(os.Stdout, inc)
			if showEvents {
				var events []incidentEventDTO
				if err := apiGet(cmd.Context(), fs,
					"/v1/orgs/"+fs.orgSlug+"/incidents/"+args[0]+"/events", &events); err != nil {
					return err
				}
				fmt.Fprintln(os.Stdout, "\nEvents:")
				for _, e := range events {
					fmt.Fprintf(os.Stdout, "  [%s] %s", e.OccurredAt.Format(time.RFC3339), e.Kind)
					if e.FromStatus != "" && e.ToStatus != "" {
						fmt.Fprintf(os.Stdout, " %s→%s", e.FromStatus, e.ToStatus)
					}
					if e.Body != "" {
						fmt.Fprintf(os.Stdout, " — %s", e.Body)
					}
					fmt.Fprintln(os.Stdout)
				}
			}
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	cmd.Flags().BoolVar(&showEvents, "events", true, "Include the event log")
	return cmd
}

func newIncidentCommentCmd() *cobra.Command {
	var serverURL, orgSlug, token, body string
	cmd := &cobra.Command{
		Use:   "comment <incident-id>",
		Short: "Append a comment to an incident",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if strings.TrimSpace(body) == "" {
				return fmt.Errorf("--body required")
			}
			if err := apiSend(cmd.Context(), fs, "POST",
				"/v1/orgs/"+fs.orgSlug+"/incidents/"+args[0]+"/comments",
				map[string]any{"body": body}, nil); err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "comment added")
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&body, "body", "", "Comment body (required)")
	_ = cmd.MarkFlagRequired("body")
	return cmd
}

func newIncidentMitigateCmd() *cobra.Command {
	return statusTransitionCmd("mitigate", "Mark the incident mitigated", "mitigating")
}

func newIncidentResolveCmd() *cobra.Command {
	return statusTransitionCmd("resolve", "Mark the incident fully resolved", "resolved")
}

func statusTransitionCmd(verb, short, targetStatus string) *cobra.Command {
	var serverURL, orgSlug, token, comment string
	cmd := &cobra.Command{
		Use:   verb + " <incident-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{"status": targetStatus}
			if comment != "" {
				body["comment"] = comment
			}
			var inc incidentDTO
			if err := apiPatch(cmd.Context(), fs,
				"/v1/orgs/"+fs.orgSlug+"/incidents/"+args[0], body, &inc); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s — %s\n", inc.ID, inc.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&comment, "comment", "", "Comment recorded with the transition")
	return cmd
}

func newIncidentPostmortemCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		urlStr, file, comment     string
	)
	cmd := &cobra.Command{
		Use:   "postmortem <incident-id>",
		Short: "File a postmortem (markdown file or URL) and move the incident to postmortem",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if urlStr == "" && file == "" {
				return fmt.Errorf("either --url or --file is required")
			}
			body := map[string]any{"status": "postmortem"}
			if urlStr != "" {
				body["postmortem_url"] = urlStr
			}
			if file != "" {
				data, err := os.ReadFile(file)
				if err != nil {
					return fmt.Errorf("read postmortem: %w", err)
				}
				body["postmortem_markdown"] = string(data)
			}
			if comment != "" {
				body["comment"] = comment
			}
			var inc incidentDTO
			if err := apiPatch(cmd.Context(), fs,
				"/v1/orgs/"+fs.orgSlug+"/incidents/"+args[0], body, &inc); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s postmortem filed\n", inc.ID)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&urlStr, "url", "", "Postmortem URL (Notion, Confluence, etc.)")
	cmd.Flags().StringVar(&file, "file", "", "Path to a markdown postmortem to embed")
	cmd.Flags().StringVar(&comment, "comment", "", "Comment recorded with the transition")
	return cmd
}

func addProjectServerFlags(cmd *cobra.Command, serverURL, orgSlug, projectSlug, token *string) {
	addFindingsServerFlags(cmd, serverURL, orgSlug, token)
	cmd.Flags().StringVar(projectSlug, "project", "", "Project slug (defaults to active project)")
}

func printIncidents(w io.Writer, rows []incidentDTO, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no incidents")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tSTATUS\tOPENED\tTITLE")
	for _, inc := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			inc.ID, inc.Severity, inc.Status,
			inc.OpenedAt.Format(time.RFC3339),
			inc.Title)
	}
	return tw.Flush()
}

func printOneIncident(w io.Writer, inc incidentDTO) {
	fmt.Fprintf(w, "Incident   : %s\n", inc.ID)
	fmt.Fprintf(w, "Title      : %s\n", inc.Title)
	fmt.Fprintf(w, "Severity   : %s\n", inc.Severity)
	fmt.Fprintf(w, "Status     : %s\n", inc.Status)
	fmt.Fprintf(w, "Opened     : %s\n", inc.OpenedAt.Format(time.RFC3339))
	if inc.MitigatedAt != nil {
		fmt.Fprintf(w, "Mitigated  : %s\n", inc.MitigatedAt.Format(time.RFC3339))
	}
	if inc.ResolvedAt != nil {
		fmt.Fprintf(w, "Resolved   : %s\n", inc.ResolvedAt.Format(time.RFC3339))
	}
	if inc.EscalatedAt != nil {
		fmt.Fprintf(w, "Escalated  : %s\n", inc.EscalatedAt.Format(time.RFC3339))
	}
	if inc.Summary != "" {
		fmt.Fprintf(w, "Summary    : %s\n", inc.Summary)
	}
	if len(inc.AffectedControls) > 0 {
		fmt.Fprintf(w, "Controls   : %s\n", strings.Join(inc.AffectedControls, ", "))
	}
	if inc.PostmortemURL != "" {
		fmt.Fprintf(w, "Postmortem : %s\n", inc.PostmortemURL)
	}
}
