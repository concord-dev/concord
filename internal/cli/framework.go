package cli

import "github.com/spf13/cobra"

func newFrameworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "framework",
		Short: "Manage Concord framework manifests (`concord add <id>` is the user-facing equivalent for install)",
	}
	cmd.AddCommand(newFrameworkScaffoldCmd())
	return cmd
}
