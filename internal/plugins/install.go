package plugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// InstallOptions tune Install. Zero values are sensible defaults.
type InstallOptions struct {
	InstallRoot       string
	LockfilePath      string
	Platform          string
	PlainHTTP         bool
	RequireSignature  bool
	SkipSignature     bool
	AllowSignerChange bool
	ExpectedIdentity  string
	GitHubRepo        string
	CosignBin         string
	ProgressW         io.Writer
}

// Install pulls, verifies, and locks a plugin OCI artifact.
func Install(ctx context.Context, ref string, opts InstallOptions) (*PullResult, error) {
	progress := opts.ProgressW
	if progress == nil {
		progress = io.Discard
	}

	fmt.Fprintf(progress, "Pulling %s...\n", ref)
	pulled, err := PullPlugin(ctx, ref, PullOptions{
		InstallRoot: opts.InstallRoot,
		Platform:    opts.Platform,
		PlainHTTP:   opts.PlainHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("pulling %s: %w", ref, err)
	}
	fmt.Fprintf(progress, "  → digest %s\n", pulled.Digest)
	fmt.Fprintf(progress, "  → installed %s\n", pulled.BinaryPath)

	verify, err := runVerification(ctx, pulled, opts, progress)
	if err != nil {
		_ = os.Remove(pulled.BinaryPath)
		return nil, err
	}

	if err := writeLockEntry(opts.LockfilePath, pulled, verify, opts.AllowSignerChange); err != nil {
		return nil, err
	}
	fmt.Fprintln(progress, "  → lockfile updated")
	return pulled, nil
}

func runVerification(ctx context.Context, pulled *PullResult, opts InstallOptions, progress io.Writer) (*VerifyResult, error) {
	if opts.SkipSignature {
		fmt.Fprintln(progress, "  → signature verification SKIPPED (--no-verify)")
		return nil, nil
	}
	signedRef := pulled.Artifact + "@" + pulled.Digest
	repo := opts.GitHubRepo
	if repo == "" {
		repo = guessGitHubRepoFromArtifact(pulled.Artifact)
	}
	verifyOpts := VerifyOptions{
		Identity:  opts.ExpectedIdentity,
		CosignBin: opts.CosignBin,
	}
	if verifyOpts.Identity == "" && repo != "" {
		verifyOpts.IdentityRegexp = IdentityRegexpForGitHubRepo(repo)
	}
	if verifyOpts.Identity == "" && verifyOpts.IdentityRegexp == "" {
		if opts.RequireSignature {
			return nil, errors.New("--require-signature was set, but no identity could be determined from artifact reference (pass --identity or --identity-regexp)")
		}
		fmt.Fprintln(progress, "  → signature verification SKIPPED (cannot determine signer identity)")
		return nil, nil
	}

	result, err := VerifySignature(ctx, signedRef, verifyOpts)
	switch {
	case errors.Is(err, ErrCosignMissing):
		if opts.RequireSignature {
			return nil, fmt.Errorf("--require-signature was set, but cosign is not on PATH: %w", err)
		}
		fmt.Fprintln(progress, "  → signature verification SKIPPED (cosign not on PATH)")
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("verifying signature: %w", err)
	}
	fmt.Fprintf(progress, "  → signature OK (signer=%s)\n", result.Identity)
	return result, nil
}

func writeLockEntry(path string, pulled *PullResult, verify *VerifyResult, allowSignerChange bool) error {
	if path == "" {
		path = LockfilePath
	}
	lf, err := LoadLockfile(path)
	if err != nil {
		return err
	}
	signer := ""
	if verify != nil {
		signer = verify.Identity
	}
	if prev := lf.Lookup(pulled.Source); prev != nil && !allowSignerChange {
		if err := AssertSignerContinuity(prev.Signer, signer); err != nil {
			return err
		}
	}
	lf.Upsert(LockedPlugin{
		Source:      pulled.Source,
		Artifact:    pulled.Artifact,
		Version:     pulled.Version,
		Digest:      pulled.Digest,
		Signer:      signer,
		Platform:    pulled.Platform,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
	})
	return SaveLockfile(path, lf)
}

// Uninstall removes the binary on disk and drops the lockfile entry.
func Uninstall(source string, opts InstallOptions) error {
	root, err := resolveInstallRoot(opts.InstallRoot)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, source)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing %s: %w", dir, err)
	}
	lockPath := opts.LockfilePath
	if lockPath == "" {
		lockPath = LockfilePath
	}
	lf, err := LoadLockfile(lockPath)
	if err != nil {
		return err
	}
	if !lf.Remove(source) {
		return fmt.Errorf("no lockfile entry for source %q", source)
	}
	return SaveLockfile(lockPath, lf)
}

func guessGitHubRepoFromArtifact(artifact string) string {
	const prefix = "ghcr.io/"
	if !strings.HasPrefix(artifact, prefix) {
		return ""
	}
	return strings.TrimPrefix(artifact, prefix)
}
