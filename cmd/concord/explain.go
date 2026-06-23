package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
	"github.com/concord-dev/concord/pkg/controls"
)

func newExplainCmd() *cobra.Command {
	var controlsDir string
	cmd := &cobra.Command{
		Use:   "explain <CONTROL-ID>",
		Short: "Show full description, rationale, evidence, and mappings for a control",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := strings.ToLower(args[0])
			loaded, err := controls.Load(controlsDir)
			if err != nil {
				return fmt.Errorf("loading controls: %w", err)
			}
			for _, l := range loaded {
				if strings.ToLower(l.Control.Metadata.ID) == target {
					printExplain(os.Stdout, l.Control, l.Path)
					return nil
				}
			}
			return fmt.Errorf("no control with id %q (use `concord list` to see available)", args[0])
		},
	}
	cmd.Flags().StringVar(&controlsDir, "controls", "./controls", "Path to controls directory")
	return cmd
}

func newListCmd() *cobra.Command {
	var (
		controlsDir string
		framework   string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all controls in the controls directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			loaded, err := controls.Load(controlsDir)
			if err != nil {
				return fmt.Errorf("loading controls: %w", err)
			}
			cs := make([]apiv1.Control, 0, len(loaded))
			for _, l := range loaded {
				if framework != "" && l.Control.Metadata.Framework != framework {
					continue
				}
				cs = append(cs, l.Control)
			}
			sort.Slice(cs, func(i, j int) bool {
				if cs[i].Metadata.Framework != cs[j].Metadata.Framework {
					return cs[i].Metadata.Framework < cs[j].Metadata.Framework
				}
				return cs[i].Metadata.ID < cs[j].Metadata.ID
			})
			printList(os.Stdout, cs)
			return nil
		},
	}
	cmd.Flags().StringVar(&controlsDir, "controls", "./controls", "Path to controls directory")
	cmd.Flags().StringVar(&framework, "framework", "", "Filter by framework")
	return cmd
}

func printList(w io.Writer, cs []apiv1.Control) {
	if len(cs) == 0 {
		fmt.Fprintln(w, "(no controls)")
		return
	}
	fmt.Fprintf(w, "%-15s %-18s %-10s %s\n", "FRAMEWORK", "ID", "SEVERITY", "TITLE")
	for _, c := range cs {
		fmt.Fprintf(w, "%-15s %-18s %-10s %s\n",
			c.Metadata.Framework, c.Metadata.ID, c.Metadata.Severity, c.Metadata.Title)
	}
	fmt.Fprintf(w, "\n%d control(s)\n", len(cs))
}

func printExplain(w io.Writer, c apiv1.Control, path string) {
	bold := color.New(color.Bold).SprintFunc()
	dim := color.New(color.Faint).SprintFunc()

	fmt.Fprintln(w, bold(c.Metadata.ID), "—", c.Metadata.Title)
	fmt.Fprintln(w, dim(path))
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s    %s\n", bold("Framework"), c.Metadata.Framework)
	if c.Metadata.Category != "" {
		fmt.Fprintf(w, "%s     %s\n", bold("Category"), c.Metadata.Category)
	}
	fmt.Fprintf(w, "%s     %s\n", bold("Severity"), severityColored(c.Metadata.Severity))
	if c.Spec.Status != "" {
		fmt.Fprintf(w, "%s       %s\n", bold("Status"), c.Spec.Status)
	}
	fmt.Fprintf(w, "%s     %v\n", bold("Blocking"), c.Spec.Blocking)
	if len(c.Metadata.Tags) > 0 {
		fmt.Fprintf(w, "%s         %s\n", bold("Tags"), strings.Join(c.Metadata.Tags, ", "))
	}
	fmt.Fprintln(w)

	if c.Spec.Description != "" {
		fmt.Fprintln(w, bold("Description"))
		fmt.Fprintln(w, indent(strings.TrimSpace(c.Spec.Description), "  "))
		fmt.Fprintln(w)
	}
	if c.Spec.Rationale != "" {
		fmt.Fprintln(w, bold("Rationale"))
		fmt.Fprintln(w, indent(strings.TrimSpace(c.Spec.Rationale), "  "))
		fmt.Fprintln(w)
	}

	if len(c.Spec.Evidence) > 0 {
		fmt.Fprintln(w, bold("Evidence sources"))
		for _, e := range c.Spec.Evidence {
			fmt.Fprintf(w, "  - %s (source: %s, type: %s)\n", e.ID, e.Source, e.Type)
			if e.Fixture != "" {
				fmt.Fprintf(w, "      fixture: %s\n", e.Fixture)
			}
			if len(e.Params) > 0 {
				keys := mapKeys(e.Params)
				sort.Strings(keys)
				for _, k := range keys {
					fmt.Fprintf(w, "      param %s: %v\n", k, e.Params[k])
				}
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, bold("Policy"))
	fmt.Fprintf(w, "  engine:  %s\n", c.Spec.Policy.Engine)
	fmt.Fprintf(w, "  package: %s\n", c.Spec.Policy.Package)
	fmt.Fprintf(w, "  file:    %s\n", c.Spec.Policy.File)
	fmt.Fprintln(w)

	if len(c.Spec.Mappings) > 0 {
		fmt.Fprintln(w, bold("Mappings"))
		keys := make([]string, 0, len(c.Spec.Mappings))
		for k := range c.Spec.Mappings {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %s: %s\n", k, strings.Join(c.Spec.Mappings[k], ", "))
		}
		fmt.Fprintln(w)
	}

	if c.Spec.Remediation != nil {
		fmt.Fprintln(w, bold("Remediation"))
		if c.Spec.Remediation.Runbook != "" {
			fmt.Fprintf(w, "  runbook:           %s\n", c.Spec.Remediation.Runbook)
		}
		if c.Spec.Remediation.EstimatedEffort != "" {
			fmt.Fprintf(w, "  estimated_effort:  %s\n", c.Spec.Remediation.EstimatedEffort)
		}
		fmt.Fprintf(w, "  auto_fix:          %v\n", c.Spec.Remediation.AutoFix)
	}
}

func severityColored(sev string) string {
	switch sev {
	case "critical":
		return color.New(color.FgRed, color.Bold).Sprint(sev)
	case "high":
		return color.RedString(sev)
	case "medium":
		return color.YellowString(sev)
	case "low":
		return color.BlueString(sev)
	}
	return sev
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
