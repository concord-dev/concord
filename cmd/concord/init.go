package main

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord"
	"github.com/concord-dev/concord/internal/scaffold"
)

func newInitCmd() *cobra.Command {
	var (
		outputDir    string
		frameworks   []string
		githubAction bool
		force        bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold Concord controls and config into the current repo",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := scaffold.Frameworks(concord.FrameworksFS, outputDir, frameworks, force)
			if err != nil {
				return fmt.Errorf("scaffolding controls: %w", err)
			}
			for _, p := range res.Written {
				fmt.Printf("  write   %s\n", p)
			}
			for _, p := range res.Skipped {
				fmt.Printf("  skip    %s (exists; pass --force to overwrite)\n", p)
			}

			cfgPath := filepath.Join(".", "concord.yaml")
			cfgWritten, err := scaffold.Config(cfgPath, force)
			if err != nil {
				return fmt.Errorf("writing config: %w", err)
			}
			if cfgWritten {
				fmt.Printf("  write   %s\n", cfgPath)
			} else {
				fmt.Printf("  skip    %s (exists)\n", cfgPath)
			}

			if githubAction {
				wfPath := filepath.Join(".github", "workflows", "concord.yml")
				wfWritten, err := scaffold.GitHubAction(wfPath, force)
				if err != nil {
					return fmt.Errorf("writing github action: %w", err)
				}
				if wfWritten {
					fmt.Printf("  write   %s\n", wfPath)
				} else {
					fmt.Printf("  skip    %s (exists)\n", wfPath)
				}
			}

			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Println("  1. Review controls in", outputDir)
			fmt.Println("  2. Set CONCORD_GITHUB_TOKEN and CONCORD_REPO to enable the live github collector")
			fmt.Println("  3. Run: concord check --controls", outputDir)
			return nil
		},
	}
	cmd.Flags().StringVar(&outputDir, "output", "./controls", "Destination directory for controls")
	cmd.Flags().StringSliceVar(&frameworks, "framework", nil, "Frameworks to install (default: all). Repeatable.")
	cmd.Flags().BoolVar(&githubAction, "github-action", false, "Also scaffold .github/workflows/concord.yml")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing files")
	return cmd
}
