package cli

import "github.com/spf13/cobra"

// NewAdminCmd builds the concord-admin bundle: the GRC-program administration
// verbs (risk, audit, exceptions, reports, attestations, policy docs, schedules,
// vendors, incidents, access reviews, …) that manage state on a running Concord
// platform. It ships as a SEPARATE binary so the practitioner's `concord` stays
// lean (assessment/36 phase 3): the compliance admin installs concord-admin, and
// `concord admin <verb>` dispatches to it via the extension mechanism.
//
// The verbs mount directly under this root, so both `concord-admin risk list`
// and (through dispatch) `concord admin risk list` resolve the same way.
func NewAdminCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "concord-admin",
		Short: "Concord GRC program administration (requires a Concord server)",
		Long: `Server-side GRC program administration for Concord.

These verbs manage program state on a running Concord platform — risks,
exceptions, audit engagements, reports, attestations, policy documents,
schedules, vendors, incidents, access reviews, and more. They are for
compliance administrators; the engineer's local/CI loop uses the core
'concord' commands (check, plan, apply, watch).

Invoke directly (concord-admin risk list) or, with this binary on PATH, via
the lean core as 'concord admin risk list'.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	for _, ctor := range []func() *cobra.Command{
		newRiskCmd, newAssetCmd, newExceptionCmd, newEvidenceCmd, newEvidenceRequestCmd,
		newPolicyDocCmd, newAttestationCmd, newScheduleCmd, newRequirementCmd, newAuditCmd,
		newReportCmd, newRoleCmd, newCustomFieldCmd, newAuditPacketCmd, newShareCmd,
		newVendorCmd, newRemediateCmd, newSSOCmd, newIncidentCmd, newAccessReviewCmd,
		newWorkflowCmd,
		newVersionCmd, // report the bundle's version too
	} {
		root.AddCommand(ctor())
	}
	return root
}
