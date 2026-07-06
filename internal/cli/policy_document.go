package cli

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

type policyDocDTO struct {
	ID           string     `json:"id"`
	Title        string     `json:"title"`
	Status       string     `json:"status"`
	Version      int        `json:"version"`
	Category     string     `json:"category,omitempty"`
	Body         string     `json:"body,omitempty"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
	ReviewDueAt  *time.Time `json:"review_due_at,omitempty"`
	DecisionNote string     `json:"decision_note,omitempty"`
}

func policyDocBase(fs findingsServer) string { return "/v1/orgs/" + fs.orgSlug + "/policy-documents" }

func newPolicyDocCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "policy-doc",
		Aliases: []string{"pdoc"},
		Short:   "Author, approve, and publish governance policy documents",
	}
	cmd.AddCommand(newPolicyDocCreateCmd())
	cmd.AddCommand(newPolicyDocListCmd())
	cmd.AddCommand(newPolicyDocShowCmd())
	cmd.AddCommand(newPolicyDocUpdateCmd())
	cmd.AddCommand(newPolicyDocActionCmd("submit", "Submit a draft for review", false))
	cmd.AddCommand(newPolicyDocActionCmd("approve", "Approve an in-review document", true))
	cmd.AddCommand(newPolicyDocActionCmd("reject", "Reject an in-review document back to draft", true))
	cmd.AddCommand(newPolicyDocActionCmd("revise", "Reopen a published document for the next version", false))
	cmd.AddCommand(newPolicyDocActionCmd("archive", "Archive (retire) a document", true))
	cmd.AddCommand(newPolicyDocPublishCmd())
	cmd.AddCommand(newPolicyDocEventsCmd())
	return cmd
}

func newPolicyDocCreateCmd() *cobra.Command {
	var serverURL, orgSlug, token, title, body, bodyFile, category string
	var requiresAttestation bool
	var attestationDueDays, attestationRecurrenceMonths int
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Draft a new policy document",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if bodyFile != "" {
				b, err := os.ReadFile(bodyFile)
				if err != nil {
					return fmt.Errorf("--body-file: %w", err)
				}
				body = string(b)
			}
			payload := map[string]any{"title": title}
			if body != "" {
				payload["body"] = body
			}
			if category != "" {
				payload["category"] = category
			}
			if requiresAttestation {
				payload["requires_attestation"] = true
			}
			if cmd.Flags().Changed("attestation-due-days") {
				payload["attestation_due_days"] = attestationDueDays
			}
			if cmd.Flags().Changed("attestation-recurrence-months") {
				payload["attestation_recurrence_months"] = attestationRecurrenceMonths
			}
			var pd policyDocDTO
			if err := apiSend(cmd.Context(), fs, "POST", policyDocBase(fs), payload, &pd); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", pd.ID, pd.Title, pd.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&title, "title", "", "Document title (required)")
	cmd.Flags().StringVar(&body, "body", "", "Document body (markdown)")
	cmd.Flags().StringVar(&bodyFile, "body-file", "", "Read the body from a file")
	cmd.Flags().StringVar(&category, "category", "", "Free-text category")
	cmd.Flags().BoolVar(&requiresAttestation, "requires-attestation", false, "Launch an org-wide attestation campaign when this policy is published")
	cmd.Flags().IntVar(&attestationDueDays, "attestation-due-days", 0, "Days attesters get to acknowledge (use with --requires-attestation)")
	cmd.Flags().IntVar(&attestationRecurrenceMonths, "attestation-recurrence-months", 0, "Re-attest every N months (0 = one-time)")
	_ = cmd.MarkFlagRequired("title")
	return cmd
}

func newPolicyDocListCmd() *cobra.Command {
	var serverURL, orgSlug, token, status, category, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List policy documents",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			if status != "" {
				q.Set("status", status)
			}
			if category != "" {
				q.Set("category", category)
			}
			path := policyDocBase(fs)
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var rows []policyDocDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no policy documents")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATUS\tVER\tCATEGORY\tTITLE")
			for _, p := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", p.ID, p.Status, p.Version, dashIfEmpty(p.Category), p.Title)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&status, "status", "", "Filter: draft|in_review|approved|published|archived")
	cmd.Flags().StringVar(&category, "category", "", "Filter by category")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newPolicyDocShowCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one policy document",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var pd policyDocDTO
			if err := apiGet(cmd.Context(), fs, policyDocBase(fs)+"/"+args[0], &pd); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(pd)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "id\t%s\n", pd.ID)
			fmt.Fprintf(tw, "title\t%s\n", pd.Title)
			fmt.Fprintf(tw, "status\t%s\n", pd.Status)
			fmt.Fprintf(tw, "version\t%d\n", pd.Version)
			if pd.Category != "" {
				fmt.Fprintf(tw, "category\t%s\n", pd.Category)
			}
			if pd.ReviewDueAt != nil {
				fmt.Fprintf(tw, "review due\t%s\n", pd.ReviewDueAt.Format(time.RFC3339))
			}
			if pd.DecisionNote != "" {
				fmt.Fprintf(tw, "decision note\t%s\n", pd.DecisionNote)
			}
			_ = tw.Flush()
			if pd.Body != "" {
				fmt.Fprintf(os.Stdout, "\n%s\n", pd.Body)
			}
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newPolicyDocUpdateCmd() *cobra.Command {
	var serverURL, orgSlug, token, title, body, bodyFile, category string
	var requiresAttestation bool
	var attestationDueDays, attestationRecurrenceMonths int
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Edit a draft or in-review document",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			payload := map[string]any{}
			if cmd.Flags().Changed("title") {
				payload["title"] = title
			}
			if bodyFile != "" {
				b, err := os.ReadFile(bodyFile)
				if err != nil {
					return fmt.Errorf("--body-file: %w", err)
				}
				payload["body"] = string(b)
			} else if cmd.Flags().Changed("body") {
				payload["body"] = body
			}
			if cmd.Flags().Changed("category") {
				payload["category"] = category
			}
			if cmd.Flags().Changed("requires-attestation") {
				payload["requires_attestation"] = requiresAttestation
			}
			if cmd.Flags().Changed("attestation-due-days") {
				payload["attestation_due_days"] = attestationDueDays
			}
			if cmd.Flags().Changed("attestation-recurrence-months") {
				payload["attestation_recurrence_months"] = attestationRecurrenceMonths
			}
			if len(payload) == 0 {
				return fmt.Errorf("no fields to update — pass at least one flag")
			}
			var pd policyDocDTO
			if err := apiSend(cmd.Context(), fs, "PATCH", policyDocBase(fs)+"/"+args[0], payload, &pd); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", pd.ID, pd.Title, pd.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&title, "title", "", "New title")
	cmd.Flags().StringVar(&body, "body", "", "New body (markdown)")
	cmd.Flags().StringVar(&bodyFile, "body-file", "", "Read the new body from a file")
	cmd.Flags().StringVar(&category, "category", "", "New category")
	cmd.Flags().BoolVar(&requiresAttestation, "requires-attestation", false, "Launch an attestation campaign on publish")
	cmd.Flags().IntVar(&attestationDueDays, "attestation-due-days", 0, "Days attesters get to acknowledge")
	cmd.Flags().IntVar(&attestationRecurrenceMonths, "attestation-recurrence-months", 0, "Re-attest every N months (0 = one-time)")
	return cmd
}

// newPolicyDocActionCmd builds a note-carrying lifecycle transition subcommand
// (submit/approve/reject/revise/archive).
func newPolicyDocActionCmd(action, short string, withNote bool) *cobra.Command {
	var serverURL, orgSlug, token, note string
	cmd := &cobra.Command{
		Use:   action + " <id>",
		Short: short,
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
			var pd policyDocDTO
			if err := apiSend(cmd.Context(), fs, "POST", policyDocBase(fs)+"/"+args[0]+"/"+action, payload, &pd); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", pd.ID, pd.Title, pd.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	if withNote {
		cmd.Flags().StringVar(&note, "note", "", "Decision note")
	}
	return cmd
}

func newPolicyDocPublishCmd() *cobra.Command {
	var serverURL, orgSlug, token, reviewDue string
	cmd := &cobra.Command{
		Use:   "publish <id>",
		Short: "Publish an approved document (bumps version)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			payload := map[string]any{}
			if reviewDue != "" {
				t, err := parseUntil(reviewDue)
				if err != nil {
					return fmt.Errorf("--review-due: %w", err)
				}
				payload["review_due_at"] = t.Format(time.RFC3339)
			}
			var pd policyDocDTO
			if err := apiSend(cmd.Context(), fs, "POST", policyDocBase(fs)+"/"+args[0]+"/publish", payload, &pd); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (published v%d)\n", pd.ID, pd.Title, pd.Version)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&reviewDue, "review-due", "", "Next periodic-review date (RFC3339 or duration like 1y)")
	return cmd
}

func newPolicyDocEventsCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "events <id>",
		Short: "Show a policy document's change history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var events []riskEventDTO
			if err := apiGet(cmd.Context(), fs, policyDocBase(fs)+"/"+args[0]+"/events", &events); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(events)
			}
			printLifecycleEvents(os.Stdout, events)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

// printLifecycleEvents renders a from→to / details audit trail (shared by the
// policy-doc and attestation event views).
func printLifecycleEvents(w io.Writer, events []riskEventDTO) {
	if len(events) == 0 {
		fmt.Fprintln(w, "no events")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "WHEN\tKIND\tDETAIL")
	for _, e := range events {
		detail := ""
		if e.FromStatus != "" || e.ToStatus != "" {
			detail = e.FromStatus + " → " + e.ToStatus
		} else if len(e.Details) > 0 {
			detail = compactJSON(e.Details)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", e.OccurredAt.Format(time.RFC3339), e.Kind, detail)
	}
	_ = tw.Flush()
}
