package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/scaffold"
)

func newScaffoldRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scaffold",
		Short: "Scaffold a new control YAML + Rego skeleton inside an existing control pack",
	}
	cmd.AddCommand(newScaffoldControlCmd())
	return cmd
}

func newScaffoldControlCmd() *cobra.Command {
	var (
		dest, pack, id, title, framework, severity, author, description, tmplFlag string
		force                                                                     bool
	)
	cmd := &cobra.Command{
		Use:   "control",
		Short: "Write controls/<id>.yaml + policies/<id>.rego + pass/fail fixtures",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dest == "" {
				dest = "."
			}
			tmpl, err := scaffold.ParseTemplate(tmplFlag)
			if err != nil {
				return err
			}
			r, err := scaffold.Control(dest, scaffold.ControlInput{
				Pack:        pack,
				ID:          id,
				Title:       title,
				Framework:   framework,
				Severity:    severity,
				Author:      author,
				Description: description,
				Template:    tmpl,
			}, force)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, "Scaffolded:")
			fmt.Fprintf(os.Stdout, "  %s\n", r.YAML)
			fmt.Fprintf(os.Stdout, "  %s\n", r.Rego)
			fmt.Fprintf(os.Stdout, "  %s\n", r.PassFix)
			fmt.Fprintf(os.Stdout, "  %s\n", r.FailFix)
			for _, p := range r.LibFiles {
				fmt.Fprintf(os.Stdout, "  %s\n", p)
			}
			fmt.Fprintln(os.Stdout, "Next steps:")
			fmt.Fprintln(os.Stdout, "  - flesh out evidence params and the deny rules in the rego file")
			fmt.Fprintln(os.Stdout, "  - validate with `concord control validate ./controls/<id>.yaml`")
			return nil
		},
	}
	cmd.Flags().StringVar(&dest, "output", "", "Control-pack root (default: current directory)")
	cmd.Flags().StringVar(&pack, "pack", "", "Pack name; used as the Rego package prefix (required)")
	cmd.Flags().StringVar(&id, "id", "", "Control id (e.g. MYCORP-1.1) (required)")
	cmd.Flags().StringVar(&title, "title", "", "Human-readable control title")
	cmd.Flags().StringVar(&framework, "framework", "", "Framework id this control belongs to (defaults to --pack)")
	cmd.Flags().StringVar(&severity, "severity", "medium", "Severity: low|medium|high|critical")
	cmd.Flags().StringVar(&author, "author", "", "Owning team or author (default: concord-dev)")
	cmd.Flags().StringVar(&description, "description", "", "Long-form description (multi-line OK)")
	cmd.Flags().StringVar(&tmplFlag, "template", "generic",
		"Template: generic|aws-resource|gcp-resource|azure-resource|k8s-resource|github-policy|policy-attestation|vendor-cert|composite")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing files")
	_ = cmd.MarkFlagRequired("pack")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}
