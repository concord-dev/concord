// Command concord-admin is the first-party GRC-administration bundle for
// Concord: risk, audit, exceptions, reports, attestations, policy docs,
// schedules, vendors, incidents, access reviews, and more. It ships separately
// from the lean core `concord` so a practitioner installs only what they use;
// with concord-admin on PATH, `concord admin <verb>` dispatches here via the
// extension mechanism (assessment/36 phase 3).
package main

import (
	"fmt"
	"os"

	"github.com/concord-dev/concord/internal/cli"
)

func main() {
	if err := cli.NewAdminCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
