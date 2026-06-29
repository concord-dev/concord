package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

type requirementCoverageDTO struct {
	RequirementID      string `json:"requirement_id"`
	Label              string `json:"label"`
	Title              string `json:"title"`
	ControlCount       int    `json:"control_count"`
	PassingControls    int    `json:"passing_controls"`
	FailingControls    int    `json:"failing_controls"`
	UnassessedControls int    `json:"unassessed_controls"`
	Status             string `json:"status"`
	Applicable         bool   `json:"applicable"`
}

type readinessSummaryDTO struct {
	Framework     string  `json:"framework"`
	Version       string  `json:"version"`
	Baseline      string  `json:"baseline"`
	Total         int     `json:"total"`
	Applicable    int     `json:"applicable"`
	Met           int     `json:"met"`
	Partial       int     `json:"partial"`
	Unmet         int     `json:"unmet"`
	NotAssessed   int     `json:"not_assessed"`
	NotApplicable int     `json:"not_applicable"`
	ReadinessPct  float64 `json:"readiness_pct"`
}

type controlStatusDTO struct {
	ControlID string `json:"control_id"`
	Status    string `json:"status"`
}

type requirementDetailDTO struct {
	RequirementID      string             `json:"requirement_id"`
	Title              string             `json:"title"`
	Status             string             `json:"status"`
	Applicable         bool               `json:"applicable"`
	ImplStatus         string             `json:"impl_status"`
	ControlCount       int                `json:"control_count"`
	PassingControls    int                `json:"passing_controls"`
	FailingControls    int                `json:"failing_controls"`
	UnassessedControls int                `json:"unassessed_controls"`
	Controls           []controlStatusDTO `json:"controls"`
}

func requirementBase(fs findingsServer) string {
	return "/v1/orgs/" + fs.orgSlug + "/requirements"
}

func newRequirementCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "requirement",
		Aliases: []string{"req", "requirements"},
		Short:   "Inspect framework requirements and clause-level readiness",
	}
	cmd.AddCommand(newRequirementCoverageCmd())
	cmd.AddCommand(newRequirementReadinessCmd())
	cmd.AddCommand(newRequirementShowCmd())
	return cmd
}

func newRequirementCoverageCmd() *cobra.Command {
	var serverURL, orgSlug, token, framework, version, baseline, format string
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Per-requirement readiness for a framework",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			q.Set("framework", framework)
			if version != "" {
				q.Set("version", version)
			}
			if baseline != "" {
				q.Set("baseline", baseline)
			}
			var rows []requirementCoverageDTO
			if err := apiGet(cmd.Context(), fs, requirementBase(fs)+"/coverage?"+q.Encode(), &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no requirements")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "REQUIREMENT\tSTATUS\tCONTROLS(P/F/T)\tTITLE")
			for _, c := range rows {
				label := c.RequirementID
				if c.Label != "" {
					label = c.Label
				}
				fmt.Fprintf(tw, "%s\t%s\t%d/%d/%d\t%s\n",
					label, c.Status, c.PassingControls, c.FailingControls, c.ControlCount, c.Title)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&framework, "framework", "", "Framework key (required)")
	cmd.Flags().StringVar(&version, "version", "", "Framework version")
	cmd.Flags().StringVar(&baseline, "baseline", "", "Restrict to a baseline")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	_ = cmd.MarkFlagRequired("framework")
	return cmd
}

func newRequirementReadinessCmd() *cobra.Command {
	var serverURL, orgSlug, token, framework, version, baseline, format string
	cmd := &cobra.Command{
		Use:   "readiness",
		Short: "Framework readiness scorecard (clause-level rollup)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			q.Set("framework", framework)
			if version != "" {
				q.Set("version", version)
			}
			if baseline != "" {
				q.Set("baseline", baseline)
			}
			var sum readinessSummaryDTO
			if err := apiGet(cmd.Context(), fs, requirementBase(fs)+"/readiness?"+q.Encode(), &sum); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(sum)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "framework\t%s\n", sum.Framework)
			fmt.Fprintf(tw, "readiness\t%.1f%% (%d met / %d applicable)\n", sum.ReadinessPct, sum.Met, sum.Applicable)
			fmt.Fprintf(tw, "met\t%d\n", sum.Met)
			fmt.Fprintf(tw, "partial\t%d\n", sum.Partial)
			fmt.Fprintf(tw, "unmet\t%d\n", sum.Unmet)
			fmt.Fprintf(tw, "not_assessed\t%d\n", sum.NotAssessed)
			fmt.Fprintf(tw, "not_applicable\t%d\n", sum.NotApplicable)
			fmt.Fprintf(tw, "total\t%d\n", sum.Total)
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&framework, "framework", "", "Framework key (required)")
	cmd.Flags().StringVar(&version, "version", "", "Framework version")
	cmd.Flags().StringVar(&baseline, "baseline", "", "Restrict to a baseline")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	_ = cmd.MarkFlagRequired("framework")
	return cmd
}

func newRequirementShowCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one requirement's readiness with its control tree",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var d requirementDetailDTO
			if err := apiGet(cmd.Context(), fs, requirementBase(fs)+"/"+args[0]+"/readiness", &d); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(d)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "requirement\t%s\n", d.RequirementID)
			fmt.Fprintf(tw, "title\t%s\n", d.Title)
			fmt.Fprintf(tw, "status\t%s\n", d.Status)
			fmt.Fprintf(tw, "applicable\t%t\n", d.Applicable)
			fmt.Fprintf(tw, "controls\t%d passing, %d failing, %d unassessed (of %d)\n",
				d.PassingControls, d.FailingControls, d.UnassessedControls, d.ControlCount)
			if err := tw.Flush(); err != nil {
				return err
			}
			if len(d.Controls) > 0 {
				ct := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(ct, "CONTROL\tSTATUS")
				for _, c := range d.Controls {
					fmt.Fprintf(ct, "%s\t%s\n", c.ControlID, c.Status)
				}
				return ct.Flush()
			}
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}
