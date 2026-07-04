package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/lockfile"
	"github.com/concord-dev/concord/internal/ociart"
	"github.com/concord-dev/concord/internal/plugins"
)

func newPluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage Concord plugins (low-level — prefer `concord add <framework>` once available)",
	}
	cmd.AddCommand(newPluginInstallCmd())
	cmd.AddCommand(newPluginListCmd())
	cmd.AddCommand(newPluginRemoveCmd())
	cmd.AddCommand(newPluginVerifyCmd())
	cmd.AddCommand(newPluginScaffoldCmd())
	return cmd
}

func newPluginInstallCmd() *cobra.Command {
	var opts plugins.InstallOptions
	var requireSignature bool
	var skipSignature bool
	cmd := &cobra.Command{
		Use:   "install <oci-ref>",
		Short: "Install a plugin from an OCI registry",
		Long: `install pulls a plugin OCI artifact (ghcr.io/concord-dev/concord-plugin-<source>@<version>),
verifies its cosign keyless signature against the expected GitHub workflow
identity, writes the binary under ~/.concord/plugins/<source>/<version>/,
and pins the digest + signer in concord.lock.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.RequireSignature = requireSignature || !skipSignature // fail-closed by default
			opts.SkipSignature = skipSignature
			opts.ProgressW = os.Stderr

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			pulled, err := plugins.Install(ctx, args[0], opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s %s installed at %s\n", pulled.Source, pulled.Version, pulled.BinaryPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.InstallRoot, "install-root", "", "Override install root (default: ~/.concord/plugins)")
	cmd.Flags().StringVar(&opts.LockfilePath, "lockfile", lockfile.Path, "Path to concord.lock")
	cmd.Flags().StringVar(&opts.Platform, "platform", "", "Override target platform (default: current GOOS/GOARCH)")
	cmd.Flags().StringVar(&opts.GitHubRepo, "github-repo", "", "GitHub repo for cosign identity check (default: inferred from ghcr.io/<owner>/<repo>)")
	cmd.Flags().StringVar(&opts.ExpectedIdentity, "identity", "", "Exact cosign signer identity to require")
	cmd.Flags().BoolVar(&opts.AllowSignerChange, "allow-signer-change", false, "Permit upgrades that change the signer identity recorded in the lockfile")
	cmd.Flags().BoolVar(&requireSignature, "require-signature", false, "(default) Require a valid cosign signature; verification is on unless --no-verify")
	cmd.Flags().BoolVar(&skipSignature, "no-verify", false, "Skip signature verification entirely (use only for trusted local dev)")
	cmd.Flags().BoolVar(&opts.PlainHTTP, "plain-http", false, "Use HTTP for the registry (local testing only)")
	cmd.Flags().StringVar(&opts.CosignBin, "cosign-bin", "", "Override cosign binary path (default: lookup on PATH)")
	return cmd
}

func newPluginListCmd() *cobra.Command {
	var lockPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List installed plugins as recorded in concord.lock",
		RunE: func(cmd *cobra.Command, args []string) error {
			lf, err := lockfile.Load(lockPath)
			if err != nil {
				return err
			}
			if len(lf.Plugins) == 0 {
				fmt.Fprintln(os.Stderr, "no plugins installed")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "SOURCE\tVERSION\tDIGEST\tSIGNER")
			for _, p := range lf.Plugins {
				signer := p.Signer
				if signer == "" {
					signer = "—"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Source, p.Version, shortDigest(p.Digest), signer)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&lockPath, "lockfile", lockfile.Path, "Path to concord.lock")
	return cmd
}

func newPluginRemoveCmd() *cobra.Command {
	var opts plugins.InstallOptions
	cmd := &cobra.Command{
		Use:   "remove <source>",
		Short: "Remove an installed plugin and drop its lockfile entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := plugins.Uninstall(args[0], opts); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s removed\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.InstallRoot, "install-root", "", "Override install root (default: ~/.concord/plugins)")
	cmd.Flags().StringVar(&opts.LockfilePath, "lockfile", lockfile.Path, "Path to concord.lock")
	return cmd
}

func newPluginVerifyCmd() *cobra.Command {
	var lockPath string
	var cosignBin string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Re-verify every locked plugin's signature against its recorded signer identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			lf, err := lockfile.Load(lockPath)
			if err != nil {
				return err
			}
			if len(lf.Plugins) == 0 {
				fmt.Fprintln(os.Stderr, "no plugins to verify")
				return nil
			}
			fail := 0
			for _, p := range lf.Plugins {
				ref := p.Artifact + "@" + p.Digest
				if p.Signer == "" {
					fmt.Fprintf(os.Stdout, "  ? %s — no signer recorded in lockfile\n", p.Source)
					continue
				}
				_, err := ociart.Verify(ctx, ref, ociart.VerifyOptions{Identity: p.Signer, CosignBin: cosignBin})
				if err != nil {
					fail++
					fmt.Fprintf(os.Stdout, "  ✗ %s — %v\n", p.Source, err)
					continue
				}
				fmt.Fprintf(os.Stdout, "  ✓ %s — signer %s\n", p.Source, p.Signer)
			}
			if fail > 0 {
				return fmt.Errorf("%d plugin(s) failed verification", fail)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&lockPath, "lockfile", lockfile.Path, "Path to concord.lock")
	cmd.Flags().StringVar(&cosignBin, "cosign-bin", "", "Override cosign binary path (default: lookup on PATH)")
	return cmd
}

func shortDigest(d string) string {
	const want = "sha256:"
	if len(d) > len(want)+12 {
		return d[:len(want)+12] + "…"
	}
	return d
}
