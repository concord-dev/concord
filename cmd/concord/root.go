package main

import "github.com/spf13/cobra"

// Command groups keep the CLI lean-by-presentation: `concord --help` leads with
// the compliance-as-code core an engineer uses in CI, then the plugin/pack
// ecosystem, then server account/read verbs, and finally GRC administration
// (which only works against a running platform). See
// assessment/36-lean-cli-and-plugin-ecosystem.md for the strategy and the
// planned extraction of the admin surface.
const (
	groupCore      = "core"
	groupEcosystem = "ecosystem"
	groupAccount   = "account"
	groupAdmin     = "admin"
)

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

	cmd.AddGroup(
		&cobra.Group{ID: groupCore, Title: "Core — author & evaluate compliance as code:"},
		&cobra.Group{ID: groupEcosystem, Title: "Ecosystem — plugins, control packs & frameworks:"},
		&cobra.Group{ID: groupAccount, Title: "Account — connect to a Concord server & read results:"},
		&cobra.Group{ID: groupAdmin, Title: "Administration — GRC program management (requires a server):"},
	)
	// Keep the built-in help/completion verbs with the core so they don't dangle
	// under a separate "Additional Commands" heading.
	cmd.SetHelpCommandGroupID(groupCore)
	cmd.SetCompletionCommandGroupID(groupCore)

	// add registers a command into a help group. Grouping lives here, in one
	// place, rather than being threaded through 49 command constructors.
	add := func(group string, c *cobra.Command) {
		c.GroupID = group
		cmd.AddCommand(c)
	}

	// Core — the lean as-code loop; works offline against local controls.
	add(groupCore, newInitCmd())
	add(groupCore, newCheckCmd())
	add(groupCore, newWatchCmd())
	add(groupCore, newDiffCmd())
	add(groupCore, newExplainCmd())
	add(groupCore, newListCmd())
	add(groupCore, newPushCmd())
	add(groupCore, newControlCmd())
	add(groupCore, newScaffoldRootCmd())
	add(groupCore, newEvidenceTypeCmd())
	add(groupCore, newDoctorCmd())
	add(groupCore, newVersionCmd())

	// Ecosystem — the plugin + signed-content-pack + framework registry surface.
	add(groupEcosystem, newPluginCmd())
	add(groupEcosystem, newControlpackCmd())
	add(groupEcosystem, newFrameworkCmd())
	add(groupEcosystem, newInstallCmd())
	add(groupEcosystem, newAddCmd())
	add(groupEcosystem, newRemoveCmd())
	add(groupEcosystem, newOutdatedCmd())
	add(groupEcosystem, newOSCALCmd())

	// Account — connect to a server and read back pushed results.
	add(groupAccount, newLoginCmd())
	add(groupAccount, newLogoutCmd())
	add(groupAccount, newWhoamiCmd())
	add(groupAccount, newOrgsCmd())
	add(groupAccount, newProjectCmd())
	add(groupAccount, newRunsCmd())
	add(groupAccount, newFindingsCmd())
	add(groupAccount, newScoreCmd())
	add(groupAccount, newProvenanceCmd())
	add(groupAccount, newAgentCmd())

	// Administration — platform GRC CRUD. These live under a single `admin`
	// parent so the top-level CLI stays lean (assessment/36 phase 2). Each is
	// also kept as a HIDDEN top-level alias during the POC so existing
	// invocations (`concord risk …`) keep working while muscle memory adjusts.
	adminCtors := []func() *cobra.Command{
		newRiskCmd, newAssetCmd, newExceptionCmd, newEvidenceCmd, newEvidenceRequestCmd,
		newPolicyDocCmd, newAttestationCmd, newScheduleCmd, newRequirementCmd, newAuditCmd,
		newReportCmd, newRoleCmd, newCustomFieldCmd, newAuditPacketCmd, newShareCmd,
		newVendorCmd, newRemediateCmd, newSSOCmd, newIncidentCmd, newAccessReviewCmd,
		newWorkflowCmd,
	}
	adminCmd := newAdminCmd()
	for _, ctor := range adminCtors {
		adminCmd.AddCommand(ctor()) // canonical: `concord admin <verb>`
		alias := ctor()             // fresh instance for the back-compat path
		alias.Hidden = true
		alias.GroupID = groupAdmin
		cmd.AddCommand(alias) // hidden: `concord <verb>` (POC back-compat)
	}
	add(groupAdmin, adminCmd)

	return cmd
}
