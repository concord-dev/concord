package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type attestationCountsDTO struct {
	Total    int `json:"total"`
	Attested int `json:"attested"`
	Pending  int `json:"pending"`
	Agreed   int `json:"agreed"`
	Rejected int `json:"rejected"`
}

type attestationCampaignDTO struct {
	ID               string               `json:"id"`
	PolicyDocumentID string               `json:"policy_document_id"`
	PolicyVersion    int                  `json:"policy_version"`
	Title            string               `json:"title"`
	Status           string               `json:"status"`
	DueAt            *time.Time           `json:"due_at,omitempty"`
	Counts           attestationCountsDTO `json:"counts"`
}

type attestationItemDTO struct {
	AttesterEmail string     `json:"attester_email"`
	AttestedAt    *time.Time `json:"attested_at,omitempty"`
	Agreed        *bool      `json:"agreed,omitempty"`
	Note          string     `json:"note,omitempty"`
}

func attestationBase(fs findingsServer) string {
	return "/v1/orgs/" + fs.orgSlug + "/attestation-campaigns"
}

func newAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "attestation",
		Aliases: []string{"attest"},
		Short:   "Launch and respond to policy attestation campaigns",
	}
	cmd.AddCommand(newAttestationLaunchCmd())
	cmd.AddCommand(newAttestationListCmd())
	cmd.AddCommand(newAttestationShowCmd())
	cmd.AddCommand(newAttestationItemsCmd())
	cmd.AddCommand(newAttestationAckCmd())
	cmd.AddCommand(newAttestationActionCmd("complete", "Complete a campaign once everyone has attested"))
	cmd.AddCommand(newAttestationActionCmd("cancel", "Cancel an in-progress campaign"))
	cmd.AddCommand(newAttestationEventsCmd())
	return cmd
}

func newAttestationLaunchCmd() *cobra.Command {
	var serverURL, orgSlug, token, policy, title, due string
	cmd := &cobra.Command{
		Use:   "launch",
		Short: "Launch a campaign over a published policy (snapshots the org population)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			payload := map[string]any{"policy_document_id": policy}
			if title != "" {
				payload["title"] = title
			}
			if due != "" {
				t, err := parseUntil(due)
				if err != nil {
					return fmt.Errorf("--due: %w", err)
				}
				payload["due_at"] = t.Format(time.RFC3339)
			}
			var c attestationCampaignDTO
			if err := apiSend(cmd.Context(), fs, "POST", attestationBase(fs), payload, &c); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s, %d to attest)\n", c.ID, c.Title, c.Status, c.Counts.Total)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&policy, "policy", "", "Published policy document id (required)")
	cmd.Flags().StringVar(&title, "title", "", "Campaign title (defaults to the policy title)")
	cmd.Flags().StringVar(&due, "due", "", "Due date (RFC3339 or a duration like 30d)")
	_ = cmd.MarkFlagRequired("policy")
	return cmd
}

func newAttestationListCmd() *cobra.Command {
	var serverURL, orgSlug, token, status, policy, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List attestation campaigns",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			if status != "" {
				q.Set("status", status)
			}
			if policy != "" {
				q.Set("policy_document_id", policy)
			}
			path := attestationBase(fs)
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var rows []attestationCampaignDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no attestation campaigns")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATUS\tPROGRESS\tTITLE")
			for _, c := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%d/%d\t%s\n", c.ID, c.Status, c.Counts.Attested, c.Counts.Total, c.Title)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&status, "status", "", "Filter: in_progress|completed|cancelled")
	cmd.Flags().StringVar(&policy, "policy", "", "Filter by policy document id")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newAttestationShowCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one campaign with response counts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var c attestationCampaignDTO
			if err := apiGet(cmd.Context(), fs, attestationBase(fs)+"/"+args[0], &c); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(c)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "id\t%s\n", c.ID)
			fmt.Fprintf(tw, "title\t%s\n", c.Title)
			fmt.Fprintf(tw, "status\t%s\n", c.Status)
			fmt.Fprintf(tw, "policy\t%s (v%d)\n", c.PolicyDocumentID, c.PolicyVersion)
			fmt.Fprintf(tw, "progress\t%d/%d attested (%d agreed, %d rejected, %d pending)\n",
				c.Counts.Attested, c.Counts.Total, c.Counts.Agreed, c.Counts.Rejected, c.Counts.Pending)
			if c.DueAt != nil {
				fmt.Fprintf(tw, "due\t%s\n", c.DueAt.Format(time.RFC3339))
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newAttestationItemsCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	var pending bool
	cmd := &cobra.Command{
		Use:   "items <id>",
		Short: "List a campaign's per-person attestation items",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			path := attestationBase(fs) + "/" + args[0] + "/items"
			if pending {
				path += "?pending=true"
			}
			var rows []attestationItemDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no items")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ATTESTER\tSTATE\tWHEN")
			for _, it := range rows {
				state, when := "pending", "-"
				if it.AttestedAt != nil {
					state = "agreed"
					if it.Agreed != nil && !*it.Agreed {
						state = "rejected"
					}
					when = it.AttestedAt.Format(time.RFC3339)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", it.AttesterEmail, state, when)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().BoolVar(&pending, "pending", false, "Only people who have not yet attested")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newAttestationAckCmd() *cobra.Command {
	var serverURL, orgSlug, token, note string
	var reject bool
	cmd := &cobra.Command{
		Use:   "ack <id>",
		Short: "Acknowledge (or --reject) your own item (requires a `concord login` session)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			payload := map[string]any{"agreed": !reject}
			if note != "" {
				payload["note"] = note
			}
			var it attestationItemDTO
			if err := apiSend(cmd.Context(), fs, "POST", attestationBase(fs)+"/"+args[0]+"/attest", payload, &it); err != nil {
				return err
			}
			verb := "acknowledged"
			if reject {
				verb = "rejected"
			}
			fmt.Fprintf(os.Stdout, "%s the policy\n", verb)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().BoolVar(&reject, "reject", false, "Record disagreement instead of acknowledgment")
	cmd.Flags().StringVar(&note, "note", "", "Optional note")
	return cmd
}

func newAttestationActionCmd(action, short string) *cobra.Command {
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
			var c attestationCampaignDTO
			if err := apiSend(cmd.Context(), fs, "POST", attestationBase(fs)+"/"+args[0]+"/"+action, payload, &c); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s\n", c.ID, c.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	if action == "cancel" {
		cmd.Flags().StringVar(&note, "note", "", "Reason for cancellation")
	}
	return cmd
}

func newAttestationEventsCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "events <id>",
		Short: "Show a campaign's change history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var events []riskEventDTO
			if err := apiGet(cmd.Context(), fs, attestationBase(fs)+"/"+args[0]+"/events", &events); err != nil {
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
