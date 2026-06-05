package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/controlpacks"
	"github.com/concord-dev/concord/internal/lockfile"
	"github.com/concord-dev/concord/internal/ociart"
)

func newControlpackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "controlpack",
		Short: "Manage Concord control packs (low-level — prefer `concord add <framework>` once available)",
	}
	cmd.AddCommand(newControlpackInstallCmd())
	cmd.AddCommand(newControlpackListCmd())
	cmd.AddCommand(newControlpackRemoveCmd())
	cmd.AddCommand(newControlpackVerifyCmd())
	cmd.AddCommand(newControlpackScaffoldCmd())
	return cmd
}

func newControlpackInstallCmd() *cobra.Command {
	var opts controlpacks.InstallOptions
	var requireSignature, skipSignature bool
	cmd := &cobra.Command{
		Use:   "install <oci-ref>",
		Short: "Install a control pack from an OCI registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.RequireSignature = requireSignature
			opts.SkipSignature = skipSignature
			opts.ProgressW = os.Stderr
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			installed, err := controlpacks.Install(ctx, args[0], opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s %s installed at %s (%d controls)\n",
				installed.Framework, installed.Version, installed.Dir, len(installed.Pack.Spec.Controls))
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.InstallRoot, "install-root", "", "Override install root (default: ~/.concord/controlpacks)")
	cmd.Flags().StringVar(&opts.LockfilePath, "lockfile", lockfile.Path, "Path to concord.lock")
	cmd.Flags().StringVar(&opts.GitHubRepo, "github-repo", "", "GitHub repo for cosign identity check (default: inferred from ghcr.io/<owner>/<repo>)")
	cmd.Flags().StringVar(&opts.ExpectedIdentity, "identity", "", "Exact cosign signer identity to require")
	cmd.Flags().BoolVar(&opts.AllowSignerChange, "allow-signer-change", false, "Permit upgrades that change the signer identity recorded in the lockfile")
	cmd.Flags().BoolVar(&requireSignature, "require-signature", false, "Fail if no valid cosign signature is found")
	cmd.Flags().BoolVar(&skipSignature, "no-verify", false, "Skip signature verification entirely (use only for trusted local dev)")
	cmd.Flags().BoolVar(&opts.PlainHTTP, "plain-http", false, "Use HTTP for the registry (local testing only)")
	cmd.Flags().StringVar(&opts.CosignBin, "cosign-bin", "", "Override cosign binary path (default: lookup on PATH)")
	return cmd
}

func newControlpackListCmd() *cobra.Command {
	var lockPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List installed control packs as recorded in concord.lock",
		RunE: func(cmd *cobra.Command, args []string) error {
			lf, err := lockfile.Load(lockPath)
			if err != nil {
				return err
			}
			if len(lf.ControlPacks) == 0 {
				fmt.Fprintln(os.Stderr, "no control packs installed")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "FRAMEWORK\tVERSION\tDIGEST\tSIGNER")
			for _, p := range lf.ControlPacks {
				signer := p.Signer
				if signer == "" {
					signer = "—"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Framework, p.Version, shortDigest(p.Digest), signer)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&lockPath, "lockfile", lockfile.Path, "Path to concord.lock")
	return cmd
}

func newControlpackRemoveCmd() *cobra.Command {
	var opts controlpacks.InstallOptions
	cmd := &cobra.Command{
		Use:   "remove <framework>",
		Short: "Remove an installed control pack and drop its lockfile entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := controlpacks.Uninstall(args[0], opts); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s removed\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.InstallRoot, "install-root", "", "Override install root (default: ~/.concord/controlpacks)")
	cmd.Flags().StringVar(&opts.LockfilePath, "lockfile", lockfile.Path, "Path to concord.lock")
	return cmd
}

func newControlpackVerifyCmd() *cobra.Command {
	var lockPath, cosignBin string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Re-verify every locked control pack's signature against its recorded signer identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			lf, err := lockfile.Load(lockPath)
			if err != nil {
				return err
			}
			if len(lf.ControlPacks) == 0 {
				fmt.Fprintln(os.Stderr, "no control packs to verify")
				return nil
			}
			fail := 0
			for _, p := range lf.ControlPacks {
				ref := p.Artifact + "@" + p.Digest
				if p.Signer == "" {
					fmt.Fprintf(os.Stdout, "  ? %s — no signer recorded in lockfile\n", p.Framework)
					continue
				}
				_, err := ociart.Verify(ctx, ref, ociart.VerifyOptions{Identity: p.Signer, CosignBin: cosignBin})
				if err != nil {
					fail++
					fmt.Fprintf(os.Stdout, "  ✗ %s — %v\n", p.Framework, err)
					continue
				}
				fmt.Fprintf(os.Stdout, "  ✓ %s — signer %s\n", p.Framework, p.Signer)
			}
			if fail > 0 {
				return fmt.Errorf("%d control pack(s) failed verification", fail)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&lockPath, "lockfile", lockfile.Path, "Path to concord.lock")
	cmd.Flags().StringVar(&cosignBin, "cosign-bin", "", "Override cosign binary path (default: lookup on PATH)")
	return cmd
}
