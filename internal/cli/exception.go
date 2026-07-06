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

type exceptionDTO struct {
	ID                   string     `json:"id"`
	Title                string     `json:"title"`
	ScopeType            string     `json:"scope_type"`
	ControlID            string     `json:"control_id,omitempty"`
	FindingID            string     `json:"finding_id,omitempty"`
	RiskID               string     `json:"risk_id,omitempty"`
	Status               string     `json:"status"`
	State                string     `json:"state"`
	ExpiresAt            *time.Time `json:"expires_at,omitempty"`
	Description          string     `json:"description,omitempty"`
	CompensatingControls string     `json:"compensating_controls,omitempty"`
}

type exceptionRollupDTO struct {
	Total        int            `json:"total"`
	Active       int            `json:"active"`
	ExpiringSoon int            `json:"expiring_soon"`
	ByState      map[string]int `json:"by_state"`
	ByScope      map[string]int `json:"by_scope"`
}

func newExceptionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "exception",
		Aliases: []string{"exc"},
		Short:   "Manage governed, time-boxed exceptions (risk acceptances)",
	}
	cmd.AddCommand(newExceptionRequestCmd())
	cmd.AddCommand(newExceptionListCmd())
	cmd.AddCommand(newExceptionShowCmd())
	cmd.AddCommand(newExceptionUpdateCmd())
	cmd.AddCommand(newExceptionApproveCmd())
	cmd.AddCommand(newExceptionRejectCmd())
	cmd.AddCommand(newExceptionWithdrawCmd())
	cmd.AddCommand(newExceptionRenewCmd())
	cmd.AddCommand(newExceptionEventsCmd())
	cmd.AddCommand(newExceptionCampaignCmd())
	cmd.AddCommand(newExceptionRollupCmd())
	return cmd
}

func newExceptionRequestCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	var title, scope, control, finding, risk, description, compensating, expires string
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Request a new exception",
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
			body := map[string]any{"title": title, "scope_type": scope}
			if control != "" {
				body["control_id"] = control
			}
			if finding != "" {
				body["finding_id"] = finding
			}
			if risk != "" {
				body["risk_id"] = risk
			}
			if description != "" {
				body["description"] = description
			}
			if compensating != "" {
				body["compensating_controls"] = compensating
			}
			if expires != "" {
				t, err := parseUntil(expires)
				if err != nil {
					return fmt.Errorf("--expires: %w", err)
				}
				body["expires_at"] = t.Format(time.RFC3339)
			}
			var e exceptionDTO
			if err := apiSend(cmd.Context(), fs, "POST", fs.projectBase()+"/exceptions", body, &e); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", e.ID, e.Title, e.State)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&title, "title", "", "Short title for the exception (required)")
	cmd.Flags().StringVar(&scope, "scope", "", "control|finding|other (inferred from --control/--finding if unset)")
	cmd.Flags().StringVar(&control, "control", "", "Control id this exception accepts (scope=control)")
	cmd.Flags().StringVar(&finding, "finding", "", "Finding id this exception accepts (scope=finding)")
	cmd.Flags().StringVar(&risk, "risk", "", "Optional risk id this exception accepts")
	cmd.Flags().StringVar(&description, "description", "", "Justification / rationale")
	cmd.Flags().StringVar(&compensating, "compensating", "", "Compensating controls narrative")
	cmd.Flags().StringVar(&expires, "expires", "", "Expiry (RFC3339 or a duration like 90d / 6mo)")
	_ = cmd.MarkFlagRequired("title")
	return cmd
}

func newExceptionListCmd() *cobra.Command {
	var serverURL, orgSlug, token, status, scope, control, finding, format string
	var active bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List exceptions",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			for k, v := range map[string]string{"status": status, "scope": scope, "control_id": control, "finding_id": finding} {
				if v != "" {
					q.Set(k, v)
				}
			}
			if active {
				q.Set("active", "true")
			}
			path := fs.projectBase() + "/exceptions"
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var rows []exceptionDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			printExceptions(os.Stdout, rows)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&status, "status", "", "Filter by status: pending|approved|rejected|withdrawn")
	cmd.Flags().StringVar(&scope, "scope", "", "Filter by scope: control|finding|other")
	cmd.Flags().StringVar(&control, "control", "", "Filter by control id")
	cmd.Flags().StringVar(&finding, "finding", "", "Filter by finding id")
	cmd.Flags().BoolVar(&active, "active", false, "Only currently-active (approved, unexpired) exceptions")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newExceptionShowCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one exception",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var e exceptionDTO
			if err := apiGet(cmd.Context(), fs, fs.projectBase()+"/exceptions/"+args[0], &e); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(e)
			}
			printOneException(os.Stdout, e)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newExceptionUpdateCmd() *cobra.Command {
	var serverURL, orgSlug, token, title, description, compensating, risk, expires string
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Edit a pending exception",
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
			if cmd.Flags().Changed("compensating") {
				body["compensating_controls"] = compensating
			}
			if cmd.Flags().Changed("risk") {
				body["risk_id"] = risk
			}
			if cmd.Flags().Changed("expires") {
				t, err := parseUntil(expires)
				if err != nil {
					return fmt.Errorf("--expires: %w", err)
				}
				body["expires_at"] = t.Format(time.RFC3339)
			}
			if len(body) == 0 {
				return fmt.Errorf("no fields to update — pass at least one flag")
			}
			var e exceptionDTO
			if err := apiSend(cmd.Context(), fs, "PATCH", fs.projectBase()+"/exceptions/"+args[0], body, &e); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", e.ID, e.Title, e.State)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&title, "title", "", "New title")
	cmd.Flags().StringVar(&description, "description", "", "New justification")
	cmd.Flags().StringVar(&compensating, "compensating", "", "New compensating controls narrative")
	cmd.Flags().StringVar(&risk, "risk", "", "Linked risk id")
	cmd.Flags().StringVar(&expires, "expires", "", "Expiry (RFC3339 or a duration like 90d / 6mo)")
	return cmd
}

func newExceptionApproveCmd() *cobra.Command {
	var serverURL, orgSlug, token, note, expires string
	cmd := &cobra.Command{
		Use:   "approve <id>",
		Short: "Approve a pending exception (requires exception:approve)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if note != "" {
				body["note"] = note
			}
			if expires != "" {
				t, err := parseUntil(expires)
				if err != nil {
					return fmt.Errorf("--expires: %w", err)
				}
				body["expires_at"] = t.Format(time.RFC3339)
			}
			return sendExceptionDecision(cmd, fs, "approve", args[0], body)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&note, "note", "", "Decision note")
	cmd.Flags().StringVar(&expires, "expires", "", "Set/override expiry (RFC3339 or duration like 90d)")
	return cmd
}

func newExceptionRejectCmd() *cobra.Command {
	var serverURL, orgSlug, token, note string
	cmd := &cobra.Command{
		Use:   "reject <id>",
		Short: "Reject a pending exception (requires exception:approve)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if note != "" {
				body["note"] = note
			}
			return sendExceptionDecision(cmd, fs, "reject", args[0], body)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&note, "note", "", "Decision note")
	return cmd
}

func newExceptionWithdrawCmd() *cobra.Command {
	var serverURL, orgSlug, token, note string
	cmd := &cobra.Command{
		Use:   "withdraw <id>",
		Short: "Withdraw a pending or approved exception",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if note != "" {
				body["note"] = note
			}
			return sendExceptionDecision(cmd, fs, "withdraw", args[0], body)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&note, "note", "", "Reason for withdrawal")
	return cmd
}

func newExceptionRenewCmd() *cobra.Command {
	var serverURL, orgSlug, token, note, expires string
	cmd := &cobra.Command{
		Use:   "renew <id>",
		Short: "Renew (extend the expiry of) an approved exception (requires exception:approve)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			t, err := parseUntil(expires)
			if err != nil {
				return fmt.Errorf("--expires: %w", err)
			}
			body := map[string]any{"expires_at": t.Format(time.RFC3339)}
			if note != "" {
				body["note"] = note
			}
			return sendExceptionDecision(cmd, fs, "renew", args[0], body)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&expires, "expires", "", "New expiry (RFC3339 or duration like 90d) — required")
	cmd.Flags().StringVar(&note, "note", "", "Renewal note")
	_ = cmd.MarkFlagRequired("expires")
	return cmd
}

func sendExceptionDecision(cmd *cobra.Command, fs findingsServer, action, id string, body map[string]any) error {
	var e exceptionDTO
	if err := apiSend(cmd.Context(), fs, "POST", fs.projectBase()+"/exceptions/"+id+"/"+action, body, &e); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", e.ID, e.Title, e.State)
	return nil
}

func newExceptionEventsCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "events <id>",
		Short: "Show an exception's change history (audit trail)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var events []riskEventDTO
			if err := apiGet(cmd.Context(), fs, fs.projectBase()+"/exceptions/"+args[0]+"/events", &events); err != nil {
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

func newExceptionCampaignCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "campaign <id>",
		Short: "Start the approval workflow (SLA reminder + manager escalation) for an exception",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var inst struct {
				ID string `json:"id"`
			}
			if err := apiSend(cmd.Context(), fs, "POST", fs.projectBase()+"/exceptions/"+args[0]+"/campaign", nil, &inst); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "started exception_approval campaign %s\n", inst.ID)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newExceptionRollupCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "rollup",
		Short: "Org exception posture summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var roll exceptionRollupDTO
			if err := apiGet(cmd.Context(), fs, "/v1/orgs/"+fs.orgSlug+"/exceptions/rollup", &roll); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(roll)
			}
			fmt.Fprintf(os.Stdout, "total %d | active %d | expiring-soon %d\n", roll.Total, roll.Active, roll.ExpiringSoon)
			printCountMap(os.Stdout, "by state", roll.ByState)
			printCountMap(os.Stdout, "by scope", roll.ByScope)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func printExceptions(w io.Writer, rows []exceptionDTO) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "no exceptions")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tSCOPE\tTARGET\tEXPIRES\tTITLE")
	for _, e := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			e.ID, e.State, e.ScopeType, exceptionTarget(e), exceptionExpiry(e), e.Title)
	}
	_ = tw.Flush()
}

func printOneException(w io.Writer, e exceptionDTO) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "id\t%s\n", e.ID)
	fmt.Fprintf(tw, "title\t%s\n", e.Title)
	fmt.Fprintf(tw, "status\t%s\n", e.Status)
	fmt.Fprintf(tw, "state\t%s\n", e.State)
	fmt.Fprintf(tw, "scope\t%s\n", e.ScopeType)
	if t := exceptionTarget(e); t != "-" {
		fmt.Fprintf(tw, "target\t%s\n", t)
	}
	if e.RiskID != "" {
		fmt.Fprintf(tw, "risk\t%s\n", e.RiskID)
	}
	fmt.Fprintf(tw, "expires\t%s\n", exceptionExpiry(e))
	if e.Description != "" {
		fmt.Fprintf(tw, "rationale\t%s\n", e.Description)
	}
	if e.CompensatingControls != "" {
		fmt.Fprintf(tw, "compensating\t%s\n", e.CompensatingControls)
	}
	_ = tw.Flush()
}

func exceptionTarget(e exceptionDTO) string {
	switch {
	case e.ControlID != "":
		return e.ControlID
	case e.FindingID != "":
		return e.FindingID
	default:
		return "-"
	}
}

func exceptionExpiry(e exceptionDTO) string {
	if e.ExpiresAt == nil {
		return "never"
	}
	return e.ExpiresAt.Format(time.RFC3339)
}

func printCountMap(w io.Writer, label string, m map[string]int) {
	if len(m) == 0 {
		return
	}
	fmt.Fprintf(w, "%s:", label)
	for k, v := range m {
		fmt.Fprintf(w, " %s=%d", k, v)
	}
	fmt.Fprintln(w)
}
