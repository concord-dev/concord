package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type engagementDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Framework   string `json:"framework"`
	Status      string `json:"status"`
	LeadAuditor string `json:"lead_auditor"`
}

type pbcDTO struct {
	ID            string     `json:"id"`
	EngagementID  string     `json:"engagement_id"`
	Title         string     `json:"title"`
	Status        string     `json:"status"`
	AssigneeEmail string     `json:"assignee_email"`
	DueAt         *time.Time `json:"due_at,omitempty"`
}

func engagementBase(fs findingsServer) string { return "/v1/orgs/" + fs.orgSlug + "/engagements" }
func pbcBase(fs findingsServer) string        { return "/v1/orgs/" + fs.orgSlug + "/pbc-requests" }

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Manage audit engagements and PBC (Provided-By-Client) requests",
	}
	cmd.AddCommand(newEngagementCmd())
	cmd.AddCommand(newPBCCmd())
	return cmd
}

func newEngagementCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "engagement", Aliases: []string{"eng"}, Short: "Audit engagements"}
	cmd.AddCommand(newEngagementCreateCmd())
	cmd.AddCommand(newEngagementListCmd())
	cmd.AddCommand(newEngagementShowCmd())
	for _, a := range []string{"start", "review", "complete", "cancel"} {
		cmd.AddCommand(newEngagementActionCmd(a))
	}
	return cmd
}

func newEngagementCreateCmd() *cobra.Command {
	var serverURL, orgSlug, token, name, framework, lead string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Open an audit engagement",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			payload := map[string]any{"name": name}
			if framework != "" {
				payload["framework"] = framework
			}
			if lead != "" {
				payload["lead_auditor"] = lead
			}
			var e engagementDTO
			if err := apiSend(cmd.Context(), fs, "POST", engagementBase(fs), payload, &e); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", e.ID, e.Name, e.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&name, "name", "", "Engagement name (required)")
	cmd.Flags().StringVar(&framework, "framework", "", "Framework key")
	cmd.Flags().StringVar(&lead, "lead", "", "Lead auditor")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newEngagementListCmd() *cobra.Command {
	var serverURL, orgSlug, token, status, framework, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit engagements",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			if status != "" {
				q.Set("status", status)
			}
			if framework != "" {
				q.Set("framework", framework)
			}
			path := engagementBase(fs)
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var rows []engagementDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no engagements")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATUS\tFRAMEWORK\tNAME")
			for _, e := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.ID, e.Status, dashIfEmpty(e.Framework), e.Name)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&status, "status", "", "Filter: planned|in_fieldwork|in_review|completed|cancelled")
	cmd.Flags().StringVar(&framework, "framework", "", "Filter by framework")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newEngagementShowCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one engagement",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var e engagementDTO
			if err := apiGet(cmd.Context(), fs, engagementBase(fs)+"/"+args[0], &e); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(e)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "id\t%s\n", e.ID)
			fmt.Fprintf(tw, "name\t%s\n", e.Name)
			fmt.Fprintf(tw, "status\t%s\n", e.Status)
			fmt.Fprintf(tw, "framework\t%s\n", dashIfEmpty(e.Framework))
			fmt.Fprintf(tw, "lead\t%s\n", dashIfEmpty(e.LeadAuditor))
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newEngagementActionCmd(action string) *cobra.Command {
	var serverURL, orgSlug, token, note string
	cmd := &cobra.Command{
		Use:   action + " <id>",
		Short: action + " an engagement",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var payload map[string]any
			if action == "cancel" && note != "" {
				payload = map[string]any{"note": note}
			}
			var e engagementDTO
			if err := apiSend(cmd.Context(), fs, "POST", engagementBase(fs)+"/"+args[0]+"/"+action, payload, &e); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s\n", e.ID, e.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	if action == "cancel" {
		cmd.Flags().StringVar(&note, "note", "", "Reason for cancellation")
	}
	return cmd
}

func newPBCCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pbc", Short: "Provided-By-Client requests"}
	cmd.AddCommand(newPBCCreateCmd())
	cmd.AddCommand(newPBCListCmd())
	cmd.AddCommand(newPBCShowCmd())
	for _, a := range []string{"submit", "accept", "reject", "cancel"} {
		cmd.AddCommand(newPBCActionCmd(a))
	}
	return cmd
}

func newPBCCreateCmd() *cobra.Command {
	var serverURL, orgSlug, token, engagement, title, assignee, control string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Open a PBC request under an engagement",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			payload := map[string]any{"engagement_id": engagement, "title": title, "assignee_email": assignee}
			if control != "" {
				payload["control_id"] = control
			}
			var p pbcDTO
			if err := apiSend(cmd.Context(), fs, "POST", pbcBase(fs), payload, &p); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", p.ID, p.Title, p.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&engagement, "engagement", "", "Engagement id (required)")
	cmd.Flags().StringVar(&title, "title", "", "Request title (required)")
	cmd.Flags().StringVar(&assignee, "assignee", "", "Assignee email (required)")
	cmd.Flags().StringVar(&control, "control", "", "Related control id")
	_ = cmd.MarkFlagRequired("engagement")
	_ = cmd.MarkFlagRequired("title")
	_ = cmd.MarkFlagRequired("assignee")
	return cmd
}

func newPBCListCmd() *cobra.Command {
	var serverURL, orgSlug, token, engagement, status, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List PBC requests",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			if engagement != "" {
				q.Set("engagement_id", engagement)
			}
			if status != "" {
				q.Set("status", status)
			}
			path := pbcBase(fs)
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var rows []pbcDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no pbc requests")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATUS\tASSIGNEE\tTITLE")
			for _, p := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.ID, p.Status, p.AssigneeEmail, p.Title)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&engagement, "engagement", "", "Filter by engagement id")
	cmd.Flags().StringVar(&status, "status", "", "Filter: open|submitted|accepted|rejected|cancelled")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newPBCShowCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one PBC request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var p pbcDTO
			if err := apiGet(cmd.Context(), fs, pbcBase(fs)+"/"+args[0], &p); err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(p)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newPBCActionCmd(action string) *cobra.Command {
	var serverURL, orgSlug, token, note string
	cmd := &cobra.Command{
		Use:   action + " <id>",
		Short: action + " a PBC request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var payload map[string]any
			if note != "" {
				payload = map[string]any{"note": note}
			}
			var p pbcDTO
			if err := apiSend(cmd.Context(), fs, "POST", pbcBase(fs)+"/"+args[0]+"/"+action, payload, &p); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s\n", p.ID, p.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	if action != "submit" {
		cmd.Flags().StringVar(&note, "note", "", "Decision note")
	}
	return cmd
}
