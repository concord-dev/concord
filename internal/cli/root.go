package cli

import "github.com/spf13/cobra"

// Command groups keep the CLI lean-by-presentation: `concord --help` leads with
// the compliance-as-code core an engineer uses in CI, then the plugin/pack
// ecosystem, then server account/read verbs. GRC administration is NOT in the
// core surface — it ships as the concord-admin bundle (NewAdminCmd) and is
// reached via `concord admin …` through the extension dispatch. See
// assessment/36-lean-cli-and-plugin-ecosystem.md.
const (
	groupCore      = "core"
	groupEcosystem = "ecosystem"
	groupAccount   = "account"
)

// NewConcordCmd builds the lean core CLI: the as-code loop (init/check/plan/
// apply/watch/…), the ecosystem entrypoints (plugins/packs/frameworks/
// extensions), and thin account/read verbs. It deliberately excludes the ~21
// GRC-admin CRUD verbs, which live in the separately-installed concord-admin
// bundle; `concord admin <verb>` dispatches there via the extension mechanism.
func NewConcordCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "concord",
		Short: "Compliance as code, for engineering teams",
		Long: `Concord is the open-source compliance platform built for engineers.
Controls live in Git. Evidence is auto-collected from your stack.
Audits become continuous instead of episodic.

GRC program administration (risk, audit, exceptions, …) ships separately as
concord-admin; run 'concord admin <verb>' with it installed.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddGroup(
		&cobra.Group{ID: groupCore, Title: "Core — author & evaluate compliance as code:"},
		&cobra.Group{ID: groupEcosystem, Title: "Ecosystem — plugins, control packs & frameworks:"},
		&cobra.Group{ID: groupAccount, Title: "Account — connect to a Concord server & read results:"},
	)
	// Keep the built-in help/completion verbs with the core so they don't dangle
	// under a separate "Additional Commands" heading.
	cmd.SetHelpCommandGroupID(groupCore)
	cmd.SetCompletionCommandGroupID(groupCore)

	// add registers a command into a help group. Grouping lives here, in one
	// place, rather than being threaded through each command constructor.
	add := func(group string, c *cobra.Command) {
		c.GroupID = group
		cmd.AddCommand(c)
	}

	// Core — the lean as-code loop; works offline against local controls.
	// plan/apply are the Terraform-shaped verbs: `check` evaluates and prints,
	// `plan` gates a change against a baseline, `apply` records the run.
	add(groupCore, newInitCmd())
	add(groupCore, newCheckCmd())
	add(groupCore, newPlanCmd())
	add(groupCore, newApplyCmd())
	add(groupCore, newWatchCmd())
	add(groupCore, newDiffCmd())
	add(groupCore, newExplainCmd())
	add(groupCore, newListCmd())
	add(groupCore, newControlCmd())
	add(groupCore, newScaffoldRootCmd())
	add(groupCore, newEvidenceTypeCmd())
	add(groupCore, newDoctorCmd())
	add(groupCore, newVersionCmd())

	// push is superseded by `apply` (evaluate + record) and `apply --findings`
	// (record a pre-computed file). Kept as a hidden alias for POC back-compat.
	pushAlias := newPushCmd()
	pushAlias.Hidden = true
	pushAlias.GroupID = groupCore
	cmd.AddCommand(pushAlias)

	// Ecosystem — the plugin + signed-content-pack + framework registry surface,
	// plus the extension dispatch that reaches concord-admin and community verbs.
	add(groupEcosystem, newPluginCmd())
	add(groupEcosystem, newControlpackCmd())
	add(groupEcosystem, newFrameworkCmd())
	add(groupEcosystem, newInstallCmd())
	add(groupEcosystem, newAddCmd())
	add(groupEcosystem, newRemoveCmd())
	add(groupEcosystem, newOutdatedCmd())
	add(groupEcosystem, newOSCALCmd())
	add(groupEcosystem, newExtensionCmd())

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

	return cmd
}
