package plugins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/concord-dev/concord/internal/lockfile"
	"github.com/concord-dev/concord/internal/ociart"
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

// InstalledPlugin describes a successfully installed plugin.
type InstalledPlugin struct {
	Source     string
	Version    string
	Artifact   string
	Digest     string
	Platform   string
	BinaryPath string
}

// Install pulls, verifies, and locks a plugin OCI artifact.
func Install(ctx context.Context, ref string, opts InstallOptions) (*InstalledPlugin, error) {
	progress := opts.ProgressW
	if progress == nil {
		progress = io.Discard
	}

	fmt.Fprintf(progress, "Pulling %s...\n", ref)
	pulled, err := ociart.Pull(ctx, ref, ociart.PullOptions{
		Platform:  opts.Platform,
		PlainHTTP: opts.PlainHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("pulling %s: %w", ref, err)
	}

	source := ociart.Annotation(pulled.Annotations, ociart.AnnotationPluginSource)
	if source == "" {
		source = defaultSourceFromArtifact(pulled.Artifact)
	}
	if source == "" {
		return nil, fmt.Errorf("artifact missing %s annotation; cannot determine plugin source", ociart.AnnotationPluginSource)
	}

	binaryPath, err := writeBinary(opts.InstallRoot, source, pulled.Tag, pulled.Layer.Bytes)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(progress, "  → digest %s\n", pulled.Digest)
	fmt.Fprintf(progress, "  → installed %s\n", binaryPath)

	verify, err := verifyArtifact(ctx, pulled, opts, progress)
	if err != nil {
		_ = os.Remove(binaryPath)
		return nil, err
	}

	if err := writeCapabilitiesSidecar(filepath.Dir(binaryPath), binaryPath); err != nil {
		fmt.Fprintf(progress, "  → warning: capabilities sidecar not written: %v\n", err)
	}

	if err := writeLockEntry(opts.LockfilePath, source, pulled, verify, opts.AllowSignerChange); err != nil {
		return nil, err
	}
	fmt.Fprintln(progress, "  → lockfile updated")

	return &InstalledPlugin{
		Source:     source,
		Version:    pulled.Tag,
		Artifact:   pulled.Artifact,
		Digest:     pulled.Digest,
		Platform:   pulled.Platform,
		BinaryPath: binaryPath,
	}, nil
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
		lockPath = lockfile.Path
	}
	lf, err := lockfile.Load(lockPath)
	if err != nil {
		return err
	}
	if !lf.RemovePlugin(source) {
		return fmt.Errorf("no lockfile entry for source %q", source)
	}
	return lockfile.Save(lockPath, lf)
}

func writeBinary(installRoot, source, version string, content []byte) (string, error) {
	root, err := resolveInstallRoot(installRoot)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(root, source, version, "concord-plugin-"+source)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", fmt.Errorf("creating install dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".concord-plugin.*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return "", fmt.Errorf("writing binary: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return "", fmt.Errorf("chmod binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return "", fmt.Errorf("renaming binary into place: %w", err)
	}
	return dest, nil
}

func verifyArtifact(ctx context.Context, pulled *ociart.PullResult, opts InstallOptions, progress io.Writer) (*ociart.VerifyResult, error) {
	if opts.SkipSignature {
		fmt.Fprintln(progress, "  → signature verification SKIPPED (--no-verify)")
		return nil, nil
	}
	signedRef := pulled.Artifact + "@" + pulled.Digest
	repo := opts.GitHubRepo
	if repo == "" {
		repo = ociart.DefaultGitHubRepoFromArtifact(pulled.Artifact)
	}
	verifyOpts := ociart.VerifyOptions{
		Identity:  opts.ExpectedIdentity,
		CosignBin: opts.CosignBin,
	}
	if verifyOpts.Identity == "" && repo != "" {
		verifyOpts.IdentityRegexp = ociart.IdentityRegexpForGitHubRepo(repo)
	}
	if verifyOpts.Identity == "" && verifyOpts.IdentityRegexp == "" {
		if opts.RequireSignature {
			return nil, errors.New("--require-signature was set, but no identity could be determined from artifact reference (pass --identity or --identity-regexp)")
		}
		fmt.Fprintln(progress, "  → signature verification SKIPPED (cannot determine signer identity)")
		return nil, nil
	}

	result, err := ociart.Verify(ctx, signedRef, verifyOpts)
	switch {
	case errors.Is(err, ociart.ErrCosignMissing):
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

func writeLockEntry(path, source string, pulled *ociart.PullResult, verify *ociart.VerifyResult, allowSignerChange bool) error {
	if path == "" {
		path = lockfile.Path
	}
	lf, err := lockfile.Load(path)
	if err != nil {
		return err
	}
	signer := ""
	if verify != nil {
		signer = verify.Identity
	}
	if prev := lf.LookupPlugin(source); prev != nil && !allowSignerChange {
		if err := ociart.AssertSignerContinuity(prev.Signer, signer); err != nil {
			return err
		}
	}
	lf.UpsertPlugin(lockfile.LockedPlugin{
		Source:      source,
		Artifact:    pulled.Artifact,
		Version:     pulled.Tag,
		Digest:      pulled.Digest,
		Signer:      signer,
		Platform:    pulled.Platform,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
	})
	return lockfile.Save(path, lf)
}

// writeCapabilitiesSidecar spawns the newly-installed binary once to capture
// its self-declared RequiredEnv + OptionalEnv, then records them next to the
// binary so future Discover() calls can scope the env without a probe.
func writeCapabilitiesSidecar(versionDir, binPath string) error {
	mgr := New(Options{Dirs: []string{filepath.Dir(filepath.Dir(versionDir))}})
	if err := mgr.Discover(); err != nil {
		return err
	}
	defer func() { _ = mgr.Shutdown(context.Background()) }()

	source := filepath.Base(filepath.Dir(versionDir))
	caps, err := mgr.Capabilities(context.Background(), source)
	if err != nil {
		return err
	}
	return WriteAllowedEnv(versionDir, caps.RequiredEnv, caps.OptionalEnv)
}

func resolveInstallRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home dir: %w", err)
	}
	return filepath.Join(home, ".concord", "plugins"), nil
}

func defaultSourceFromArtifact(artifact string) string {
	base := artifact
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '/' {
			base = base[i+1:]
			break
		}
	}
	const prefix = "concord-plugin-"
	if len(base) > len(prefix) && base[:len(prefix)] == prefix {
		return base[len(prefix):]
	}
	return ""
}
