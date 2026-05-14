package main

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/concord-dev/concord"
	"github.com/concord-dev/concord/internal/scaffold"
)

func newUpgradeCmd() *cobra.Command {
	var (
		outputDir  string
		frameworks []string
		apply      bool
	)
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Compare local controls against the embedded library; apply with --apply",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := scaffold.Upgrade(concord.FrameworksFS, outputDir, frameworks, apply)
			if err != nil {
				return fmt.Errorf("comparing controls: %w", err)
			}

			for _, p := range res.New {
				fmt.Printf("  %s  %s\n", color.GreenString("+ new   "), p)
			}
			for _, p := range res.Modified {
				fmt.Printf("  %s  %s\n", color.YellowString("~ change"), p)
			}
			for _, p := range res.Unchanged {
				fmt.Printf("  %s  %s\n", color.New(color.Faint).Sprint("= same  "), p)
			}

			fmt.Println()
			fmt.Printf("%d new · %d changed · %d unchanged\n", len(res.New), len(res.Modified), len(res.Unchanged))

			if !apply && (len(res.New) > 0 || len(res.Modified) > 0) {
				fmt.Println()
				fmt.Println("Preview only. Re-run with --apply to write the changes.")
			} else if apply {
				fmt.Println("Applied.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&outputDir, "output", "./controls", "Path to controls directory")
	cmd.Flags().StringSliceVar(&frameworks, "framework", nil, "Frameworks to compare (default: all). Repeatable.")
	cmd.Flags().BoolVar(&apply, "apply", false, "Apply the upgrade (default: preview only)")
	return cmd
}
