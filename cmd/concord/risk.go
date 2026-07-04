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

type riskDTO struct {
	ID                 string    `json:"id"`
	Title              string    `json:"title"`
	Description        string    `json:"description,omitempty"`
	Category           string    `json:"category,omitempty"`
	InherentLikelihood int       `json:"inherent_likelihood"`
	InherentImpact     int       `json:"inherent_impact"`
	InherentScore      int       `json:"inherent_score"`
	InherentSeverity   string    `json:"inherent_severity"`
	ResidualLikelihood *int      `json:"residual_likelihood,omitempty"`
	ResidualImpact     *int      `json:"residual_impact,omitempty"`
	ResidualScore      *int      `json:"residual_score,omitempty"`
	ResidualSeverity   string    `json:"residual_severity,omitempty"`
	AppetiteThreshold  *int      `json:"appetite_threshold,omitempty"`
	AppetiteBreached   bool      `json:"appetite_breached"`
	Treatment          string    `json:"treatment"`
	Status             string    `json:"status"`
	LinkedFindingIDs   []string  `json:"linked_finding_ids,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func newRiskCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Track organisational risks and link them to findings",
	}
	cmd.AddCommand(newRiskAddCmd())
	cmd.AddCommand(newRiskListCmd())
	cmd.AddCommand(newRiskShowCmd())
	cmd.AddCommand(newRiskUpdateCmd())
	cmd.AddCommand(newRiskLinkCmd())
	cmd.AddCommand(newRiskUnlinkCmd())
	cmd.AddCommand(newRiskEventsCmd())
	cmd.AddCommand(newRiskTreatmentCmd())
	cmd.AddCommand(newRiskKRICmd())
	cmd.AddCommand(newRiskAppetiteCmd())
	cmd.AddCommand(newRiskRollupCmd())
	cmd.AddCommand(newRiskImportCmd())
	cmd.AddCommand(newRiskExportCmd())
	return cmd
}

func newRiskImportCmd() *cobra.Command {
	var serverURL, orgSlug, projectSlug, token string
	cmd := &cobra.Command{
		Use:   "import <file.csv>",
		Short: "Bulk-import risks from CSV (title,inherent_likelihood,inherent_impact,...); all-or-nothing",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(serverURL, orgSlug, projectSlug, token)
			if err != nil {
				return err
			}
			out, err := apiUploadCSV(cmd.Context(), fs, fs.projectBase()+"/risks/import", args[0])
			if err != nil {
				return err
			}
			var res struct {
				Imported int `json:"imported"`
			}
			if err := json.Unmarshal(out, &res); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "imported %d risk(s)\n", res.Imported)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	addProjectFlag(cmd, &projectSlug)
	return cmd
}

func newRiskExportCmd() *cobra.Command {
	var serverURL, orgSlug, projectSlug, token, out string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the risk register as CSV",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveServer(serverURL, orgSlug, projectSlug, token)
			if err != nil {
				return err
			}
			data, err := apiDownload(cmd.Context(), fs, fs.projectBase()+"/risks/export")
			if err != nil {
				return err
			}
			return writeOutOrStdout(out, data)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	addProjectFlag(cmd, &projectSlug)
	cmd.Flags().StringVar(&out, "out", "", "Write to file instead of stdout")
	return cmd
}

func newRiskAddCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		title, description        string
		category                  string
		likelihood, impact        int
		treatment                 string
		linkFindings              []string
		format                    string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Open a new risk",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{
				"title":               title,
				"inherent_likelihood": likelihood,
				"inherent_impact":     impact,
			}
			if description != "" {
				body["description"] = description
			}
			if category != "" {
				body["category"] = category
			}
			if treatment != "" {
				body["treatment"] = treatment
			}
			if len(linkFindings) > 0 {
				body["link_finding_ids"] = linkFindings
			}
			var r riskDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				fs.projectBase()+"/risks", body, &r); err != nil {
				return err
			}
			return printOneRisk(os.Stdout, r, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&title, "title", "", "Short risk name (required)")
	cmd.Flags().StringVar(&description, "description", "", "Long-form narrative")
	cmd.Flags().StringVar(&category, "category", "", "Risk category/taxonomy (e.g. operational, security)")
	cmd.Flags().IntVar(&likelihood, "likelihood", 0, "Inherent likelihood, 1-5 (required)")
	cmd.Flags().IntVar(&impact, "impact", 0, "Inherent impact, 1-5 (required)")
	cmd.Flags().StringVar(&treatment, "treatment", "", "Treatment strategy: accept|mitigate|transfer|avoid (default mitigate)")
	cmd.Flags().StringSliceVar(&linkFindings, "link", nil, "Finding ids to link at creation (repeatable)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	_ = cmd.MarkFlagRequired("title")
	_ = cmd.MarkFlagRequired("likelihood")
	_ = cmd.MarkFlagRequired("impact")
	return cmd
}

func newRiskListCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		statusFilter              []string
		format                    string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List risks for this org",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			for _, s := range statusFilter {
				q.Add("status", s)
			}
			path := fs.projectBase() + "/risks"
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var rows []riskDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			return printRisks(os.Stdout, rows, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringSliceVar(&statusFilter, "status", nil, "Filter by lifecycle status (repeatable)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newRiskShowCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		format                    string
	)
	cmd := &cobra.Command{
		Use:   "show <risk-id>",
		Short: "Show one risk with linked findings",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var r riskDTO
			if err := apiGet(cmd.Context(), fs,
				fs.projectBase()+"/risks/"+args[0], &r); err != nil {
				return err
			}
			return printOneRisk(os.Stdout, r, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newRiskUpdateCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token      string
		title, description             string
		category                       string
		treatment, status              string
		likelihood, impact             int
		residualL, residualI           int
		clearResidualL, clearResidualI bool
	)
	cmd := &cobra.Command{
		Use:   "update <risk-id>",
		Short: "Patch fields on an existing risk",
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
			if cmd.Flags().Changed("category") {
				body["category"] = category
			}
			if cmd.Flags().Changed("treatment") {
				body["treatment"] = treatment
			}
			if cmd.Flags().Changed("status") {
				body["status"] = status
			}
			if cmd.Flags().Changed("likelihood") {
				body["inherent_likelihood"] = likelihood
			}
			if cmd.Flags().Changed("impact") {
				body["inherent_impact"] = impact
			}
			if cmd.Flags().Changed("residual-likelihood") {
				body["residual_likelihood"] = residualL
			}
			if cmd.Flags().Changed("residual-impact") {
				body["residual_impact"] = residualI
			}
			if clearResidualL {
				body["residual_likelihood"] = nil
			}
			if clearResidualI {
				body["residual_impact"] = nil
			}
			if len(body) == 0 {
				return fmt.Errorf("no fields to update — pass at least one flag")
			}
			var r riskDTO
			if err := apiSend(cmd.Context(), fs, "PATCH",
				fs.projectBase()+"/risks/"+args[0], body, &r); err != nil {
				return err
			}
			return printOneRisk(os.Stdout, r, "text")
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&title, "title", "", "New title")
	cmd.Flags().StringVar(&description, "description", "", "New description")
	cmd.Flags().StringVar(&category, "category", "", "Risk category/taxonomy")
	cmd.Flags().StringVar(&treatment, "treatment", "", "Treatment: accept|mitigate|transfer|avoid")
	cmd.Flags().StringVar(&status, "status", "", "Status: open|monitoring|closed")
	cmd.Flags().IntVar(&likelihood, "likelihood", 0, "Inherent likelihood, 1-5")
	cmd.Flags().IntVar(&impact, "impact", 0, "Inherent impact, 1-5")
	cmd.Flags().IntVar(&residualL, "residual-likelihood", 0, "Residual likelihood after treatment, 1-5")
	cmd.Flags().IntVar(&residualI, "residual-impact", 0, "Residual impact after treatment, 1-5")
	cmd.Flags().BoolVar(&clearResidualL, "clear-residual-likelihood", false, "Erase residual likelihood")
	cmd.Flags().BoolVar(&clearResidualI, "clear-residual-impact", false, "Erase residual impact")
	return cmd
}

func newRiskLinkCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "link <risk-id> <finding-id>",
		Short: "Link a finding to a risk",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if err := apiSend(cmd.Context(), fs, "POST",
				fs.projectBase()+"/risks/"+args[0]+"/links",
				map[string]any{"finding_id": args[1]}, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s ← %s\n", args[0], args[1])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newRiskUnlinkCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "unlink <risk-id> <finding-id>",
		Short: "Unlink a finding from a risk",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if err := apiDelete(cmd.Context(), fs,
				fs.projectBase()+"/risks/"+args[0]+"/links/"+args[1]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s ⊘ %s\n", args[0], args[1])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func printRisks(w io.Writer, rows []riskDTO, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no risks")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTITLE\tCATEGORY\tSCORE\tSEVERITY\tTREATMENT\tSTATUS\tAPPETITE")
	for _, r := range rows {
		score, severity := currentRiskScore(r)
		appetite := "—"
		if r.AppetiteThreshold != nil {
			appetite = fmt.Sprintf("≤%d", *r.AppetiteThreshold)
			if r.AppetiteBreached {
				appetite = "BREACH(" + appetite + ")"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			r.ID, r.Title, dashIfBlank(r.Category), score, severity, r.Treatment, r.Status, appetite)
	}
	return tw.Flush()
}

// currentRiskScore mirrors the server: residual when assessed, else inherent.
func currentRiskScore(r riskDTO) (int, string) {
	if r.ResidualScore != nil {
		return *r.ResidualScore, r.ResidualSeverity
	}
	return r.InherentScore, r.InherentSeverity
}

func dashIfBlank(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func printOneRisk(w io.Writer, r riskDTO, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(r)
	}
	fmt.Fprintf(w, "Risk      : %s\n", r.ID)
	fmt.Fprintf(w, "Title     : %s\n", r.Title)
	if r.Description != "" {
		fmt.Fprintf(w, "Detail    : %s\n", r.Description)
	}
	if r.Category != "" {
		fmt.Fprintf(w, "Category  : %s\n", r.Category)
	}
	fmt.Fprintf(w, "Inherent  : likelihood %d × impact %d = %d (%s)\n",
		r.InherentLikelihood, r.InherentImpact, r.InherentScore, r.InherentSeverity)
	if r.ResidualScore != nil {
		fmt.Fprintf(w, "Residual  : likelihood %d × impact %d = %d (%s)\n",
			*r.ResidualLikelihood, *r.ResidualImpact, *r.ResidualScore, r.ResidualSeverity)
	}
	if r.AppetiteThreshold != nil {
		status := "within appetite"
		if r.AppetiteBreached {
			status = "OVER APPETITE"
		}
		fmt.Fprintf(w, "Appetite  : ≤%d — %s\n", *r.AppetiteThreshold, status)
	}
	fmt.Fprintf(w, "Treatment : %s\n", r.Treatment)
	fmt.Fprintf(w, "Status    : %s\n", r.Status)
	if len(r.LinkedFindingIDs) > 0 {
		fmt.Fprintln(w, "Linked findings:")
		for _, id := range r.LinkedFindingIDs {
			fmt.Fprintf(w, "  - %s\n", id)
		}
	}
	return nil
}
