package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/framework"
	"github.com/concord-dev/concord/internal/lockfile"
	"github.com/concord-dev/concord/pkg/config"
)

func newInstallCmd() *cobra.Command {
	var (
		configPath        string
		lockPath          string
		plainHTTP         bool
		requireSignature  bool
		skipSignature     bool
		allowSignerChange bool
		cosignBin         string
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Resolve concord.yaml and install every framework + transitive dependency (CI entry point)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading %s: %w", configPath, err)
			}
			if len(cfg.Frameworks) == 0 {
				fmt.Fprintln(os.Stderr, "no frameworks declared in", configPath)
				return nil
			}
			plan, err := framework.Solve(ctx, workspaceRefs(cfg.Frameworks), framework.SolveOptions{PlainHTTP: plainHTTP})
			if err != nil {
				return err
			}
			describePlan(os.Stderr, plan)

			return framework.Apply(ctx, plan, framework.ApplyOptions{
				LockfilePath:      lockPath,
				PlainHTTP:         plainHTTP,
				RequireSignature:  requireSignature,
				SkipSignature:     skipSignature,
				AllowSignerChange: allowSignerChange,
				CosignBin:         cosignBin,
				ProgressW:         os.Stderr,
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "./concord.yaml", "Path to concord.yaml")
	cmd.Flags().StringVar(&lockPath, "lockfile", lockfile.Path, "Path to concord.lock")
	cmd.Flags().BoolVar(&plainHTTP, "plain-http", false, "Use HTTP for the registry (local testing only)")
	cmd.Flags().BoolVar(&requireSignature, "require-signature", false, "Fail if any artifact lacks a valid cosign signature")
	cmd.Flags().BoolVar(&skipSignature, "no-verify", false, "Skip signature verification entirely")
	cmd.Flags().BoolVar(&allowSignerChange, "allow-signer-change", false, "Permit upgrades that change a recorded signer identity")
	cmd.Flags().StringVar(&cosignBin, "cosign-bin", "", "Override cosign binary path")
	return cmd
}
