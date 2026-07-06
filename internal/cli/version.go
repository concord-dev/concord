package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	version = "0.1.0-dev"
	commit  = "none"
	date    = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Concord version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("concord %s\n", version)
			fmt.Printf("  commit:   %s\n", commit)
			fmt.Printf("  built:    %s\n", date)
			fmt.Printf("  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
			fmt.Printf("  go:       %s\n", runtime.Version())
			return nil
		},
	}
}
