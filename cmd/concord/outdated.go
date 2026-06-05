package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/framework"
	"github.com/concord-dev/concord/internal/lockfile"
)

func newOutdatedCmd() *cobra.Command {
	var lockPath string
	cmd := &cobra.Command{
		Use:   "outdated",
		Short: "Show installed artifacts whose newest matching tag in the registry is ahead of what's pinned in concord.lock",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			lf, err := lockfile.Load(lockPath)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "KIND\tSOURCE\tINSTALLED\tLATEST")
			any := false
			for _, f := range lf.Frameworks {
				latest, _ := framework.ResolveTag(ctx, f.Artifact, "", false)
				if latest != "" && latest != f.Version {
					fmt.Fprintf(tw, "framework\t%s\t%s\t%s\n", f.ID, f.Version, latest)
					any = true
				}
			}
			for _, p := range lf.ControlPacks {
				latest, _ := framework.ResolveTag(ctx, p.Artifact, "", false)
				if latest != "" && latest != p.Version {
					fmt.Fprintf(tw, "controlpack\t%s\t%s\t%s\n", p.Framework, p.Version, latest)
					any = true
				}
			}
			for _, p := range lf.Plugins {
				latest, _ := framework.ResolveTag(ctx, p.Artifact, "", false)
				if latest != "" && latest != p.Version {
					fmt.Fprintf(tw, "plugin\t%s\t%s\t%s\n", p.Source, p.Version, latest)
					any = true
				}
			}
			if !any {
				fmt.Fprintln(os.Stderr, "all artifacts up to date")
				return nil
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&lockPath, "lockfile", lockfile.Path, "Path to concord.lock")
	return cmd
}
