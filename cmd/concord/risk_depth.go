package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type riskEventDTO struct {
	Kind       string         `json:"kind"`
	FromStatus string         `json:"from_status,omitempty"`
	ToStatus   string         `json:"to_status,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
}

type treatmentDTO struct {
	ID          string     `json:"id"`
	Strategy    string     `json:"strategy"`
	Description string     `json:"description,omitempty"`
	OwnerUserID *string    `json:"owner_user_id,omitempty"`
	DueAt       *time.Time `json:"due_at,omitempty"`
	Status      string     `json:"status"`
}

type kriDTO struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Unit           string     `json:"unit,omitempty"`
	Threshold      float64    `json:"threshold"`
	Direction      string     `json:"direction"`
	LatestValue    *float64   `json:"latest_value,omitempty"`
	LatestBreached bool       `json:"latest_breached"`
	LastMeasuredAt *time.Time `json:"last_measured_at,omitempty"`
}

type kriMeasurementDTO struct {
	Value      float64   `json:"value"`
	Breached   bool      `json:"breached"`
	Note       string    `json:"note,omitempty"`
	MeasuredAt time.Time `json:"measured_at"`
}

type appetiteDTO struct {
	ID          string `json:"id"`
	Category    string `json:"category,omitempty"`
	MaxScore    int    `json:"max_score"`
	Description string `json:"description,omitempty"`
}

type riskRollupDTO struct {
	Total            int            `json:"total"`
	ByStatus         map[string]int `json:"by_status"`
	BySeverity       map[string]int `json:"by_severity"`
	ByCategory       map[string]int `json:"by_category"`
	AppetiteBreaches int            `json:"appetite_breaches"`
	KRIBreaches      int            `json:"kri_breaches"`
	TopResidual      []struct {
		ID               string `json:"id"`
		Title            string `json:"title"`
		Score            int    `json:"score"`
		Severity         string `json:"severity"`
		AppetiteBreached bool   `json:"appetite_breached"`
	} `json:"top_residual"`
}

func newRiskEventsCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "events <risk-id>",
		Short: "Show a risk's change history (audit trail)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var events []riskEventDTO
			if err := apiGet(cmd.Context(), fs, fs.projectBase()+"/risks/"+args[0]+"/events", &events); err != nil {
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

func newRiskTreatmentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "treatment", Short: "Manage a risk's treatment plans"}
	cmd.AddCommand(newRiskTreatmentListCmd())
	cmd.AddCommand(newRiskTreatmentAddCmd())
	cmd.AddCommand(newRiskTreatmentUpdateCmd())
	return cmd
}

func newRiskTreatmentListCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "list <risk-id>",
		Short: "List a risk's treatment plans",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var plans []treatmentDTO
			if err := apiGet(cmd.Context(), fs, fs.projectBase()+"/risks/"+args[0]+"/treatments", &plans); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(plans)
			}
			printTreatments(os.Stdout, plans)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newRiskTreatmentAddCmd() *cobra.Command {
	var serverURL, orgSlug, token, strategy, description, due string
	cmd := &cobra.Command{
		Use:   "add <risk-id>",
		Short: "Open a treatment plan on a risk",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if strategy != "" {
				body["strategy"] = strategy
			}
			if description != "" {
				body["description"] = description
			}
			if due != "" {
				t, err := parseUntil(due)
				if err != nil {
					return fmt.Errorf("--due: %w", err)
				}
				body["due_at"] = t.Format(time.RFC3339)
			}
			var plan treatmentDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				fs.projectBase()+"/risks/"+args[0]+"/treatments", body, &plan); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", plan.ID, plan.Strategy, plan.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&strategy, "strategy", "", "accept|mitigate|transfer|avoid (default mitigate)")
	cmd.Flags().StringVar(&description, "description", "", "Plan narrative")
	cmd.Flags().StringVar(&due, "due", "", "Due date (RFC3339 or a duration like 30d / 8w / 6mo)")
	return cmd
}

func newRiskTreatmentUpdateCmd() *cobra.Command {
	var serverURL, orgSlug, token, strategy, status, description string
	cmd := &cobra.Command{
		Use:   "update <risk-id> <treatment-id>",
		Short: "Update a treatment plan",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if cmd.Flags().Changed("strategy") {
				body["strategy"] = strategy
			}
			if cmd.Flags().Changed("status") {
				body["status"] = status
			}
			if cmd.Flags().Changed("description") {
				body["description"] = description
			}
			if len(body) == 0 {
				return fmt.Errorf("no fields to update — pass at least one flag")
			}
			var plan treatmentDTO
			if err := apiSend(cmd.Context(), fs, "PATCH",
				fs.projectBase()+"/risks/"+args[0]+"/treatments/"+args[1], body, &plan); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s)\n", plan.ID, plan.Strategy, plan.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&strategy, "strategy", "", "accept|mitigate|transfer|avoid")
	cmd.Flags().StringVar(&status, "status", "", "planned|in_progress|completed|cancelled")
	cmd.Flags().StringVar(&description, "description", "", "Plan narrative")
	return cmd
}

func newRiskKRICmd() *cobra.Command {
	cmd := &cobra.Command{Use: "kri", Short: "Manage a risk's Key Risk Indicators"}
	cmd.AddCommand(newRiskKRIListCmd())
	cmd.AddCommand(newRiskKRIAddCmd())
	cmd.AddCommand(newRiskKRIMeasureCmd())
	return cmd
}

func newRiskKRIListCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "list <risk-id>",
		Short: "List a risk's KRIs and their latest values",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var kris []kriDTO
			if err := apiGet(cmd.Context(), fs, fs.projectBase()+"/risks/"+args[0]+"/kris", &kris); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(kris)
			}
			printKRIs(os.Stdout, kris)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newRiskKRIAddCmd() *cobra.Command {
	var serverURL, orgSlug, token, name, unit, direction string
	var threshold float64
	cmd := &cobra.Command{
		Use:   "add <risk-id>",
		Short: "Define a KRI on a risk",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{"name": name, "threshold": threshold, "direction": direction}
			if unit != "" {
				body["unit"] = unit
			}
			var k kriDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				fs.projectBase()+"/risks/"+args[0]+"/kris", body, &k); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (breach when %s %g)\n", k.ID, k.Name, k.Direction, k.Threshold)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&name, "name", "", "KRI name (required)")
	cmd.Flags().StringVar(&unit, "unit", "", "Unit (e.g. count, percent)")
	cmd.Flags().Float64Var(&threshold, "threshold", 0, "Breach threshold")
	cmd.Flags().StringVar(&direction, "direction", "gte", "gte (higher is worse) | lte (lower is worse)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newRiskKRIMeasureCmd() *cobra.Command {
	var serverURL, orgSlug, token, note string
	var value float64
	cmd := &cobra.Command{
		Use:   "measure <risk-id> <kri-id>",
		Short: "Record a KRI measurement (computes breach)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{"value": value}
			if note != "" {
				body["note"] = note
			}
			var m kriMeasurementDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				fs.projectBase()+"/risks/"+args[0]+"/kris/"+args[1]+"/measurements", body, &m); err != nil {
				return err
			}
			status := "within threshold"
			if m.Breached {
				status = "BREACH"
			}
			fmt.Fprintf(os.Stdout, "recorded %g — %s\n", m.Value, status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().Float64Var(&value, "value", 0, "Measured value (required)")
	cmd.Flags().StringVar(&note, "note", "", "Optional note")
	_ = cmd.MarkFlagRequired("value")
	return cmd
}

func newRiskAppetiteCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "appetite", Short: "Manage the org's risk appetites (tolerance thresholds)"}
	cmd.AddCommand(newRiskAppetiteListCmd())
	cmd.AddCommand(newRiskAppetiteSetCmd())
	cmd.AddCommand(newRiskAppetiteDeleteCmd())
	return cmd
}

// findAppetiteByCategory returns the id of the appetite for the given category
// (empty = the org default), or "" if none exists.
func findAppetiteByCategory(rows []appetiteDTO, category string) string {
	for _, a := range rows {
		if a.Category == category {
			return a.ID
		}
	}
	return ""
}

func newRiskAppetiteListCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the org's risk appetites",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var rows []appetiteDTO
			if err := apiGet(cmd.Context(), fs, "/v1/orgs/"+fs.orgSlug+"/risk-appetites", &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no appetites — risks are unbounded until you set one")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "CATEGORY\tMAX SCORE\tDESCRIPTION")
			for _, a := range rows {
				fmt.Fprintf(tw, "%s\t%d\t%s\n", appetiteCategory(a.Category), a.MaxScore, a.Description)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newRiskAppetiteSetCmd() *cobra.Command {
	var serverURL, orgSlug, token, category, description string
	var maxScore int
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Create or update a risk appetite (org default, or per --category)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			base := "/v1/orgs/" + fs.orgSlug + "/risk-appetites"
			// Upsert: an appetite is unique per (org, category), so update the
			// existing one for this category if present, else create it.
			var existing []appetiteDTO
			if err := apiGet(cmd.Context(), fs, base, &existing); err != nil {
				return err
			}
			var a appetiteDTO
			if id := findAppetiteByCategory(existing, category); id != "" {
				body := map[string]any{"max_score": maxScore}
				if cmd.Flags().Changed("description") {
					body["description"] = description
				}
				if err := apiSend(cmd.Context(), fs, "PATCH", base+"/"+id, body, &a); err != nil {
					return err
				}
			} else {
				body := map[string]any{"max_score": maxScore}
				if category != "" {
					body["category"] = category
				}
				if description != "" {
					body["description"] = description
				}
				if err := apiSend(cmd.Context(), fs, "POST", base, body, &a); err != nil {
					return err
				}
			}
			fmt.Fprintf(os.Stdout, "appetite set: %s ≤ %d\n", appetiteCategory(a.Category), a.MaxScore)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&category, "category", "", "Category this appetite applies to (omit for the org default)")
	cmd.Flags().IntVar(&maxScore, "max-score", 0, "Maximum tolerated score, 1-25 (required)")
	cmd.Flags().StringVar(&description, "description", "", "Optional description")
	_ = cmd.MarkFlagRequired("max-score")
	return cmd
}

func newRiskAppetiteDeleteCmd() *cobra.Command {
	var serverURL, orgSlug, token, category string
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a risk appetite (org default, or per --category)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			base := "/v1/orgs/" + fs.orgSlug + "/risk-appetites"
			var existing []appetiteDTO
			if err := apiGet(cmd.Context(), fs, base, &existing); err != nil {
				return err
			}
			id := findAppetiteByCategory(existing, category)
			if id == "" {
				return fmt.Errorf("no appetite for category %q", appetiteCategory(category))
			}
			if err := apiDelete(cmd.Context(), fs, base+"/"+id); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "appetite deleted: %s\n", appetiteCategory(category))
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&category, "category", "", "Category whose appetite to delete (omit for the org default)")
	return cmd
}

func newRiskRollupCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "rollup",
		Short: "Show the org's risk posture (counts, breaches, top risks)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var roll riskRollupDTO
			if err := apiGet(cmd.Context(), fs, "/v1/orgs/"+fs.orgSlug+"/risks/rollup", &roll); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(roll)
			}
			printRollup(os.Stdout, roll)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func printTreatments(w io.Writer, plans []treatmentDTO) {
	if len(plans) == 0 {
		fmt.Fprintln(w, "no treatment plans")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTRATEGY\tSTATUS\tDUE\tDESCRIPTION")
	for _, p := range plans {
		due := "—"
		if p.DueAt != nil {
			due = p.DueAt.Format("2006-01-02")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.Strategy, p.Status, due, p.Description)
	}
	_ = tw.Flush()
}

func printKRIs(w io.Writer, kris []kriDTO) {
	if len(kris) == 0 {
		fmt.Fprintln(w, "no KRIs")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tTHRESHOLD\tLATEST\tBREACHED")
	for _, k := range kris {
		latest := "—"
		if k.LatestValue != nil {
			latest = fmt.Sprintf("%g", *k.LatestValue)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s %g\t%s\t%t\n", k.ID, k.Name, k.Direction, k.Threshold, latest, k.LatestBreached)
	}
	_ = tw.Flush()
}

func printRollup(w io.Writer, roll riskRollupDTO) {
	fmt.Fprintf(w, "Total risks      : %d\n", roll.Total)
	fmt.Fprintf(w, "Appetite breaches: %d (active)\n", roll.AppetiteBreaches)
	fmt.Fprintf(w, "KRI breaches     : %d\n", roll.KRIBreaches)
	fmt.Fprintf(w, "By status        : %s\n", compactCounts(roll.ByStatus))
	fmt.Fprintf(w, "By severity      : %s\n", compactCounts(roll.BySeverity))
	fmt.Fprintf(w, "By category      : %s\n", compactCounts(roll.ByCategory))
	if len(roll.TopResidual) > 0 {
		fmt.Fprintln(w, "Top residual risks:")
		for _, t := range roll.TopResidual {
			flag := ""
			if t.AppetiteBreached {
				flag = " ⚠ over appetite"
			}
			fmt.Fprintf(w, "  %s  %d (%s)  %s%s\n", t.ID, t.Score, t.Severity, t.Title, flag)
		}
	}
}

func compactCounts(m map[string]int) string {
	if len(m) == 0 {
		return "—"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func appetiteCategory(c string) string {
	if c == "" {
		return "(default)"
	}
	return c
}
