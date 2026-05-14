package main

import "github.com/spf13/cobra"

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "concord",
		Short: "Compliance as code, for engineering teams",
		Long: `Concord is the open-source compliance platform built for engineers.
Controls live in Git. Evidence is auto-collected from your stack.
Audits become continuous instead of episodic.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newCheckCmd())
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newExplainCmd())
	cmd.AddCommand(newDoctorCmd())
	cmd.AddCommand(newWatchCmd())
	cmd.AddCommand(newDiffCmd())
	cmd.AddCommand(newUpgradeCmd())
	cmd.AddCommand(newVersionCmd())
	return cmd
}
