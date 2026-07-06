// Command concord is the lean core CLI — the compliance-as-code loop plus the
// ecosystem entrypoints. GRC administration ships separately as concord-admin
// and is reached via `concord admin …` through the extension dispatch.
package main

import (
	"os"

	"github.com/concord-dev/concord/internal/cli"
)

func main() {
	os.Exit(cli.Main())
}
