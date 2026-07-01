package main

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/scaffold"
)

func newInitCmd() *cobra.Command {
	var (
		githubAction bool
		force        bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold Concord config into the current repo",
		RunE: func(cmd *cobra.Command, args []string) error {
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
			fmt.Println("  1. Install a framework's controls: concord add soc2")
			fmt.Println("  2. Set collector credentials (e.g. CONCORD_GITHUB_TOKEN) and install its plugin")
			fmt.Println("  3. Run: concord check")
			return nil
		},
	}
	cmd.Flags().BoolVar(&githubAction, "github-action", false, "Also scaffold .github/workflows/concord.yml")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing files")
	return cmd
}
