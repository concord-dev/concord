package cli

import (
	"fmt"
	"os"
)

// Main runs the lean core CLI and returns the process exit code. It first tries
// git/gh-style extension dispatch (an unknown command backed by a concord-<name>
// binary on PATH — including concord-admin for `concord admin …`); builtins,
// flags, and unknown-with-no-binary fall through to cobra unchanged.
func Main() int {
	root := NewConcordCmd()
	if code, handled := tryExtension(root, os.Args[1:]); handled {
		return code
	}
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}
