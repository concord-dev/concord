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
	cmd.AddCommand(newPushCmd())
	cmd.AddCommand(newLoginCmd())
	cmd.AddCommand(newLogoutCmd())
	cmd.AddCommand(newWhoamiCmd())
	cmd.AddCommand(newOrgsCmd())
	cmd.AddCommand(newPluginCmd())
	cmd.AddCommand(newControlpackCmd())
	cmd.AddCommand(newAddCmd())
	cmd.AddCommand(newRemoveCmd())
	cmd.AddCommand(newInstallCmd())
	cmd.AddCommand(newOutdatedCmd())
	cmd.AddCommand(newFrameworkCmd())
	cmd.AddCommand(newFindingsCmd())
	cmd.AddCommand(newEvidenceCmd())
	cmd.AddCommand(newRiskCmd())
	cmd.AddCommand(newExceptionCmd())
	cmd.AddCommand(newEvidenceRequestCmd())
	cmd.AddCommand(newPolicyDocCmd())
	cmd.AddCommand(newAttestationCmd())
	cmd.AddCommand(newScheduleCmd())
	cmd.AddCommand(newScaffoldRootCmd())
	cmd.AddCommand(newAuditPacketCmd())
	cmd.AddCommand(newShareCmd())
	cmd.AddCommand(newVendorCmd())
	cmd.AddCommand(newRunsCmd())
	cmd.AddCommand(newProjectCmd())
	cmd.AddCommand(newRemediateCmd())
	cmd.AddCommand(newSSOCmd())
	cmd.AddCommand(newScoreCmd())
	cmd.AddCommand(newIncidentCmd())
	cmd.AddCommand(newAccessReviewCmd())
	cmd.AddCommand(newWorkflowCmd())
	cmd.AddCommand(newProvenanceCmd())
	cmd.AddCommand(newControlCmd())
	cmd.AddCommand(newEvidenceTypeCmd())
	cmd.AddCommand(newOSCALCmd())
	return cmd
}
