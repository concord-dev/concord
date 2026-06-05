package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/pkg/config"
	"github.com/concord-dev/concord/internal/framework"
	"github.com/concord-dev/concord/internal/lockfile"
)

func newRemoveCmd() *cobra.Command {
	var configPath, lockPath string
	cmd := &cobra.Command{
		Use:   "remove <framework>",
		Short: "Remove a framework from this workspace (drops the lockfile entry, leaves transitive deps in place)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading %s: %w", configPath, err)
			}
			ref := parseFrameworkArg(args[0])
			cfg.Frameworks = dropFrameworkRef(cfg.Frameworks, ref.Source)
			if err := saveConfig(configPath, cfg); err != nil {
				return fmt.Errorf("updating %s: %w", configPath, err)
			}

			lf, err := lockfile.Load(lockPath)
			if err != nil {
				return err
			}
			frameworkID := guessFrameworkID(lf, ref.Source)
			if err := framework.Remove(frameworkID, lockPath); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Removed framework %s from %s and %s.\n", frameworkID, configPath, lockPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "./concord.yaml", "Path to concord.yaml")
	cmd.Flags().StringVar(&lockPath, "lockfile", lockfile.Path, "Path to concord.lock")
	return cmd
}

func dropFrameworkRef(refs []config.FrameworkRef, source string) []config.FrameworkRef {
	out := refs[:0]
	for _, r := range refs {
		if r.Source != source {
			out = append(out, r)
		}
	}
	return out
}

func guessFrameworkID(lf *lockfile.Lockfile, artifact string) string {
	for _, f := range lf.Frameworks {
		if f.Artifact == artifact {
			return f.ID
		}
	}
	return artifact
}
