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

type evidenceRequestDTO struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	ScopeType     string     `json:"scope_type"`
	ControlID     string     `json:"control_id,omitempty"`
	FindingID     string     `json:"finding_id,omitempty"`
	AssigneeEmail string     `json:"assignee_email"`
	Status        string     `json:"status"`
	DueAt         *time.Time `json:"due_at,omitempty"`
	Recurrence    string     `json:"recurrence,omitempty"`
	Description   string     `json:"description,omitempty"`
}

type linkedAttachmentDTO struct {
	AttachmentID string `json:"attachment_id"`
	SHA256       string `json:"sha256"`
	Filename     string `json:"filename"`
	ContentType  string `json:"content_type,omitempty"`
	ByteSize     int64  `json:"byte_size"`
}

func newEvidenceRequestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "evidence-request",
		Aliases: []string{"evreq"},
		Short:   "Request, fulfil, and validate manual (non-API) evidence",
	}
	cmd.AddCommand(newEvidenceRequestRequestCmd())
	cmd.AddCommand(newEvidenceRequestListCmd())
	cmd.AddCommand(newEvidenceRequestShowCmd())
	cmd.AddCommand(newEvidenceRequestUpdateCmd())
	cmd.AddCommand(newEvidenceRequestAttachCmd())
	cmd.AddCommand(newEvidenceRequestDetachCmd())
	cmd.AddCommand(newEvidenceRequestAttachmentsCmd())
	cmd.AddCommand(newEvidenceRequestSubmitCmd())
	cmd.AddCommand(newEvidenceRequestAcceptCmd())
	cmd.AddCommand(newEvidenceRequestRejectCmd())
	cmd.AddCommand(newEvidenceRequestCancelCmd())
	cmd.AddCommand(newEvidenceRequestEventsCmd())
	cmd.AddCommand(newEvidenceRequestCampaignCmd())
	return cmd
}

func newEvidenceRequestRequestCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	var title, scope, control, finding, assignee, description, due, recurrence string
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Open a manual evidence request",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if scope == "" {
				switch {
				case control != "":
					scope = "control"
				case finding != "":
					scope = "finding"
				default:
					scope = "other"
				}
			}
			body := map[string]any{"title": title, "scope_type": scope, "assignee_email": assignee}
			if control != "" {
				body["control_id"] = control
			}
			if finding != "" {
				body["finding_id"] = finding
			}
			if description != "" {
				body["description"] = description
			}
			if recurrence != "" {
				body["recurrence"] = recurrence
			}
			if due != "" {
				t, err := parseUntil(due)
				if err != nil {
					return fmt.Errorf("--due: %w", err)
				}
				body["due_at"] = t.Format(time.RFC3339)
			}
			var er evidenceRequestDTO
			if err := apiSend(cmd.Context(), fs, "POST", fs.projectBase()+"/evidence-requests", body, &er); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", er.ID, er.Title, er.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&title, "title", "", "Short title for the request (required)")
	cmd.Flags().StringVar(&scope, "scope", "", "control|finding|other (inferred from --control/--finding if unset)")
	cmd.Flags().StringVar(&control, "control", "", "Control id the evidence supports (scope=control)")
	cmd.Flags().StringVar(&finding, "finding", "", "Finding id the evidence supports (scope=finding)")
	cmd.Flags().StringVar(&assignee, "assignee", "", "Email of the owner who must provide the evidence (required)")
	cmd.Flags().StringVar(&description, "description", "", "Instructions for the owner")
	cmd.Flags().StringVar(&due, "due", "", "Due date (RFC3339 or a duration like 30d / 8w)")
	cmd.Flags().StringVar(&recurrence, "recurrence", "", "none|weekly|monthly|quarterly|annual")
	_ = cmd.MarkFlagRequired("title")
	_ = cmd.MarkFlagRequired("assignee")
	return cmd
}

func newEvidenceRequestListCmd() *cobra.Command {
	var serverURL, orgSlug, token, status, scope, control, assignee, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List evidence requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			for k, v := range map[string]string{"status": status, "scope": scope, "control_id": control, "assignee": assignee} {
				if v != "" {
					q.Set(k, v)
				}
			}
			path := fs.projectBase() + "/evidence-requests"
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var rows []evidenceRequestDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			printEvidenceRequests(os.Stdout, rows)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&status, "status", "", "Filter by status: open|submitted|accepted|cancelled")
	cmd.Flags().StringVar(&scope, "scope", "", "Filter by scope: control|finding|other")
	cmd.Flags().StringVar(&control, "control", "", "Filter by control id")
	cmd.Flags().StringVar(&assignee, "assignee", "", "Filter by assignee email")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newEvidenceRequestShowCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one evidence request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var er evidenceRequestDTO
			if err := apiGet(cmd.Context(), fs, fs.projectBase()+"/evidence-requests/"+args[0], &er); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(er)
			}
			printOneEvidenceRequest(os.Stdout, er)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newEvidenceRequestUpdateCmd() *cobra.Command {
	var serverURL, orgSlug, token, title, description, assignee, due, recurrence string
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Edit an open evidence request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if cmd.Flags().Changed("title") {
				body["title"] = title
			}
			if cmd.Flags().Changed("description") {
				body["description"] = description
			}
			if cmd.Flags().Changed("assignee") {
				body["assignee_email"] = assignee
			}
			if cmd.Flags().Changed("recurrence") {
				body["recurrence"] = recurrence
			}
			if cmd.Flags().Changed("due") {
				t, err := parseUntil(due)
				if err != nil {
					return fmt.Errorf("--due: %w", err)
				}
				body["due_at"] = t.Format(time.RFC3339)
			}
			if len(body) == 0 {
				return fmt.Errorf("no fields to update — pass at least one flag")
			}
			var er evidenceRequestDTO
			if err := apiSend(cmd.Context(), fs, "PATCH", fs.projectBase()+"/evidence-requests/"+args[0], body, &er); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", er.ID, er.Title, er.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&title, "title", "", "New title")
	cmd.Flags().StringVar(&description, "description", "", "New instructions")
	cmd.Flags().StringVar(&assignee, "assignee", "", "New assignee email")
	cmd.Flags().StringVar(&due, "due", "", "New due date (RFC3339 or duration like 30d)")
	cmd.Flags().StringVar(&recurrence, "recurrence", "", "none|weekly|monthly|quarterly|annual")
	return cmd
}

func newEvidenceRequestAttachCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "attach <id> <attachment-id>",
		Short: "Link an uploaded attachment to a request (upload first with `concord attachment upload`)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{"attachment_id": args[1]}
			if err := apiSend(cmd.Context(), fs, "POST", fs.projectBase()+"/evidence-requests/"+args[0]+"/attachments", body, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "linked attachment %s\n", args[1])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newEvidenceRequestDetachCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "detach <id> <attachment-id>",
		Short: "Unlink an attachment from a request",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if err := apiSend(cmd.Context(), fs, "DELETE", fs.projectBase()+"/evidence-requests/"+args[0]+"/attachments/"+args[1], nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "unlinked attachment %s\n", args[1])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newEvidenceRequestAttachmentsCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "attachments <id>",
		Short: "List attachments linked to a request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var rows []linkedAttachmentDTO
			if err := apiGet(cmd.Context(), fs, fs.projectBase()+"/evidence-requests/"+args[0]+"/attachments", &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no attachments")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ATTACHMENT\tFILENAME\tBYTES\tSHA256")
			for _, a := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", a.AttachmentID, a.Filename, a.ByteSize, truncate(a.SHA256, 16))
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newEvidenceRequestSubmitCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "submit <id>",
		Short: "Submit a request for validation (requires at least one attachment)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			return sendEvidenceAction(cmd, fs, args[0], "submit", nil)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newEvidenceRequestAcceptCmd() *cobra.Command {
	var serverURL, orgSlug, token, note string
	cmd := &cobra.Command{
		Use:   "accept <id>",
		Short: "Accept a submitted request (requires evidence_request:write)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			return sendEvidenceAction(cmd, fs, args[0], "accept", decisionNoteBody(note))
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&note, "note", "", "Validation note")
	return cmd
}

func newEvidenceRequestRejectCmd() *cobra.Command {
	var serverURL, orgSlug, token, note string
	cmd := &cobra.Command{
		Use:   "reject <id>",
		Short: "Reject a submitted request back to open for rework",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			return sendEvidenceAction(cmd, fs, args[0], "reject", decisionNoteBody(note))
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&note, "note", "", "Reason for rejection")
	return cmd
}

func newEvidenceRequestCancelCmd() *cobra.Command {
	var serverURL, orgSlug, token, note string
	cmd := &cobra.Command{
		Use:   "cancel <id>",
		Short: "Cancel an open or submitted request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			return sendEvidenceAction(cmd, fs, args[0], "cancel", decisionNoteBody(note))
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&note, "note", "", "Reason for cancellation")
	return cmd
}

func decisionNoteBody(note string) map[string]any {
	if note == "" {
		return nil
	}
	return map[string]any{"note": note}
}

func sendEvidenceAction(cmd *cobra.Command, fs findingsServer, id, action string, body map[string]any) error {
	var er evidenceRequestDTO
	if err := apiSend(cmd.Context(), fs, "POST", fs.projectBase()+"/evidence-requests/"+id+"/"+action, body, &er); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", er.ID, er.Title, er.Status)
	return nil
}

func newEvidenceRequestEventsCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "events <id>",
		Short: "Show an evidence request's change history (audit trail)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var events []riskEventDTO
			if err := apiGet(cmd.Context(), fs, fs.projectBase()+"/evidence-requests/"+args[0]+"/events", &events); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(events)
			}
			if len(events) == 0 {
				fmt.Fprintln(os.Stdout, "no events")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
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
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newEvidenceRequestCampaignCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "campaign <id>",
		Short: "Start the SLA workflow (reminder + manager escalation) for a request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var inst struct {
				ID string `json:"id"`
			}
			if err := apiSend(cmd.Context(), fs, "POST", fs.projectBase()+"/evidence-requests/"+args[0]+"/campaign", nil, &inst); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "started evidence_request_campaign %s\n", inst.ID)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func printEvidenceRequests(w io.Writer, rows []evidenceRequestDTO) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "no evidence requests")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tSCOPE\tASSIGNEE\tDUE\tTITLE")
	for _, e := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			e.ID, e.Status, e.ScopeType, e.AssigneeEmail, evidenceRequestDue(e), e.Title)
	}
	_ = tw.Flush()
}

func printOneEvidenceRequest(w io.Writer, e evidenceRequestDTO) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "id\t%s\n", e.ID)
	fmt.Fprintf(tw, "title\t%s\n", e.Title)
	fmt.Fprintf(tw, "status\t%s\n", e.Status)
	fmt.Fprintf(tw, "scope\t%s\n", e.ScopeType)
	if e.ControlID != "" {
		fmt.Fprintf(tw, "control\t%s\n", e.ControlID)
	}
	if e.FindingID != "" {
		fmt.Fprintf(tw, "finding\t%s\n", e.FindingID)
	}
	fmt.Fprintf(tw, "assignee\t%s\n", e.AssigneeEmail)
	fmt.Fprintf(tw, "due\t%s\n", evidenceRequestDue(e))
	if e.Recurrence != "" && e.Recurrence != "none" {
		fmt.Fprintf(tw, "recurrence\t%s\n", e.Recurrence)
	}
	if e.Description != "" {
		fmt.Fprintf(tw, "instructions\t%s\n", e.Description)
	}
	_ = tw.Flush()
}

func evidenceRequestDue(e evidenceRequestDTO) string {
	if e.DueAt == nil {
		return "-"
	}
	return e.DueAt.Format(time.RFC3339)
}
