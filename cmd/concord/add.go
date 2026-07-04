package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/concord-dev/concord/internal/framework"
	"github.com/concord-dev/concord/internal/lockfile"
	"github.com/concord-dev/concord/pkg/config"
)

const defaultFrameworkRegistry = "ghcr.io/concord-dev/concord-framework-"

func newAddCmd() *cobra.Command {
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
		Use:   "add <framework>...",
		Short: "Add one or more compliance frameworks to this workspace",
		Long: `add resolves each named framework and its transitive control-pack +
plugin dependencies, pulls them as signed OCI artifacts, and pins the
resolved versions in concord.lock.

Arguments may be short ids (gdpr), bare OCI refs (ghcr.io/owner/repo),
or refs with a semver constraint (ghcr.io/owner/repo@^v0.1.0).`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading %s: %w", configPath, err)
			}
			for _, raw := range args {
				cfg.Frameworks = mergeFrameworkRef(cfg.Frameworks, parseFrameworkArg(raw))
			}
			refs := workspaceRefs(cfg.Frameworks)

			plan, err := framework.Solve(ctx, refs, framework.SolveOptions{PlainHTTP: plainHTTP})
			if err != nil {
				return err
			}
			describePlan(os.Stderr, plan)

			if err := framework.Apply(ctx, plan, framework.ApplyOptions{
				LockfilePath:      lockPath,
				PlainHTTP:         plainHTTP,
				RequireSignature:  requireSignature || !skipSignature, // fail-closed by default
				SkipSignature:     skipSignature,
				AllowSignerChange: allowSignerChange,
				CosignBin:         cosignBin,
				ProgressW:         os.Stderr,
			}); err != nil {
				return err
			}

			if err := saveConfig(configPath, cfg); err != nil {
				return fmt.Errorf("updating %s: %w", configPath, err)
			}
			fmt.Fprintf(os.Stdout, "\nAdded %d framework(s) to %s.\n", len(plan.Frameworks), configPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "./concord.yaml", "Path to concord.yaml")
	cmd.Flags().StringVar(&lockPath, "lockfile", lockfile.Path, "Path to concord.lock")
	cmd.Flags().BoolVar(&plainHTTP, "plain-http", false, "Use HTTP for the registry (local testing only)")
	cmd.Flags().BoolVar(&requireSignature, "require-signature", false, "(default) Require a valid cosign signature; verification is on unless --no-verify")
	cmd.Flags().BoolVar(&skipSignature, "no-verify", false, "Skip signature verification entirely")
	cmd.Flags().BoolVar(&allowSignerChange, "allow-signer-change", false, "Permit upgrades that change a recorded signer identity")
	cmd.Flags().StringVar(&cosignBin, "cosign-bin", "", "Override cosign binary path")
	return cmd
}

func parseFrameworkArg(arg string) config.FrameworkRef {
	source, version := arg, ""
	if at := strings.LastIndex(arg, "@"); at >= 0 {
		source = arg[:at]
		version = arg[at+1:]
	}
	if !strings.Contains(source, "/") {
		source = defaultFrameworkRegistry + source
	}
	return config.FrameworkRef{Source: source, Version: version}
}

func mergeFrameworkRef(existing []config.FrameworkRef, ref config.FrameworkRef) []config.FrameworkRef {
	for i, f := range existing {
		if f.Source == ref.Source {
			if ref.Version != "" {
				existing[i].Version = ref.Version
			}
			return existing
		}
	}
	return append(existing, ref)
}

func workspaceRefs(refs []config.FrameworkRef) []framework.WorkspaceRef {
	out := make([]framework.WorkspaceRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, framework.WorkspaceRef{Source: r.Source, Version: r.Version})
	}
	return out
}

func saveConfig(path string, cfg *config.Config) error {
	if cfg.APIVersion == "" {
		cfg.APIVersion = "concord.dev/v1"
	}
	if cfg.Kind == "" {
		cfg.Kind = "Workspace"
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}
	return os.WriteFile(path, raw, 0o644)
}

func describePlan(w *os.File, plan *framework.Plan) {
	fmt.Fprintf(w, "\nResolved plan:\n")
	for _, f := range plan.Frameworks {
		fmt.Fprintf(w, "  framework    %s %s\n", f.ID, f.Version)
	}
	for _, p := range plan.ControlPacks {
		fmt.Fprintf(w, "  control pack %-50s %s\n", p.Source, p.Version)
	}
	for _, p := range plan.Plugins {
		fmt.Fprintf(w, "  plugin       %-50s %s\n", p.Source, p.Version)
	}
}
