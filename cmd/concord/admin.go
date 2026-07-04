package main

import "github.com/spf13/cobra"

// newAdminCmd is the parent for server-side GRC administration verbs (risks,
// exceptions, audits, reports, attestations, policy docs, schedules, …). These
// require a running Concord platform and are used by compliance administrators,
// not in the engineer's local/CI loop — so they live under `concord admin` to
// keep the top-level CLI lean. See assessment/36-lean-cli-and-plugin-ecosystem.md.
//
// During the POC each admin verb is also kept as a HIDDEN top-level alias
// (registered in root.go) so existing invocations and muscle memory keep
// working while the surface migrates.
func newAdminCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "admin",
		Short: "GRC program administration (requires a Concord server)",
		Long: `Server-side GRC program administration.

These verbs manage program state on a running Concord platform — risks,
exceptions, audit engagements, reports, attestations, policy documents,
schedules, vendors, incidents, access reviews, and more. They are for
compliance administrators; the engineer's local/CI loop uses the core
commands (check, plan, apply, watch) instead.`,
	}
}
