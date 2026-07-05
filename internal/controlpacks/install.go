package controlpacks

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/lockfile"
	"github.com/concord-dev/concord/internal/ociart"
)

const tarMaxSize = 200 * 1024 * 1024

// InstallOptions tune Install.
type InstallOptions struct {
	InstallRoot       string
	LockfilePath      string
	PlainHTTP         bool
	RequireSignature  bool
	SkipSignature     bool
	AllowSignerChange bool
	ExpectedIdentity  string
	GitHubRepo        string
	CosignBin         string
	ProgressW         io.Writer
}

// Installed describes a successfully installed control pack.
type Installed struct {
	Framework string
	Version   string
	Artifact  string
	Digest    string
	Dir       string
	Pack      *Pack
}

// Install pulls, verifies, extracts, and locks a control-pack OCI artifact.
func Install(ctx context.Context, ref string, opts InstallOptions) (*Installed, error) {
	progress := opts.ProgressW
	if progress == nil {
		progress = io.Discard
	}

	fmt.Fprintf(progress, "Pulling %s...\n", ref)
	pulled, err := ociart.Pull(ctx, ref, ociart.PullOptions{
		Platform:  "any",
		PlainHTTP: opts.PlainHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("pulling %s: %w", ref, err)
	}

	framework := ociart.Annotation(pulled.Annotations, ociart.AnnotationPackFramework)
	if framework == "" {
		framework = defaultFrameworkFromArtifact(pulled.Artifact)
	}
	if framework == "" {
		return nil, fmt.Errorf("artifact missing %s annotation; cannot determine framework", ociart.AnnotationPackFramework)
	}

	dir, err := extractPack(opts.InstallRoot, framework, pulled.Tag, pulled.Layer.Bytes)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(progress, "  → digest %s\n", pulled.Digest)
	fmt.Fprintf(progress, "  → extracted %s\n", dir)

	pack, err := ParsePack(filepath.Join(dir, PackFile))
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("invalid pack.yaml after extraction: %w", err)
	}
	if pack.Metadata.ID != framework {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("pack.yaml metadata.id=%q does not match artifact framework annotation %q", pack.Metadata.ID, framework)
	}

	verify, err := verifyArtifact(ctx, pulled, opts, progress)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	if err := writeLockEntry(opts.LockfilePath, framework, pulled, verify, opts.AllowSignerChange); err != nil {
		return nil, err
	}
	fmt.Fprintln(progress, "  → lockfile updated")

	return &Installed{
		Framework: framework,
		Version:   pulled.Tag,
		Artifact:  pulled.Artifact,
		Digest:    pulled.Digest,
		Dir:       dir,
		Pack:      pack,
	}, nil
}

// Uninstall removes the extracted pack on disk and drops the lockfile entry.
func Uninstall(framework string, opts InstallOptions) error {
	root, err := resolveInstallRoot(opts.InstallRoot)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, framework)
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
	if !lf.RemoveControlPack(framework) {
		return fmt.Errorf("no lockfile entry for framework %q", framework)
	}
	return lockfile.Save(lockPath, lf)
}

func extractPack(installRoot, framework, version string, gzipped []byte) (string, error) {
	root, err := resolveInstallRoot(installRoot)
	if err != nil {
		return "", err
	}
	dest := PackDir(root, framework, version)

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", fmt.Errorf("creating install parent: %w", err)
	}
	if err := os.RemoveAll(dest); err != nil {
		return "", fmt.Errorf("clearing target dir: %w", err)
	}
	staging, err := os.MkdirTemp(filepath.Dir(dest), ".concord-pack.*")
	if err != nil {
		return "", fmt.Errorf("creating staging dir: %w", err)
	}
	defer os.RemoveAll(staging)

	if err := extractTarGz(bytes.NewReader(gzipped), staging); err != nil {
		return "", fmt.Errorf("extracting pack tarball: %w", err)
	}
	if err := os.Rename(staging, dest); err != nil {
		return "", fmt.Errorf("renaming staging into place: %w", err)
	}
	return dest, nil
}

func extractTarGz(src io.Reader, dest string) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("opening gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(&io.LimitedReader{R: gz, N: tarMaxSize})
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading tar header: %w", err)
		}
		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := writeFile(target, tr, os.FileMode(hdr.Mode)&0o777); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("refusing %s in pack: symlinks not allowed", hdr.Name)
		default:
			return fmt.Errorf("refusing %s in pack: unsupported tar entry type %d", hdr.Name, hdr.Typeflag)
		}
	}
}

func writeFile(path string, src io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating parent of %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	if _, err := io.Copy(f, src); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Chmod(mode | 0o600); err != nil {
		f.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return f.Close()
}

func safeJoin(root, name string) (string, error) {
	if strings.Contains(name, "\x00") {
		return "", fmt.Errorf("refusing %s in pack: NUL byte in path", name)
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("refusing %s in pack: absolute paths not allowed", name)
	}
	for _, seg := range strings.Split(filepath.ToSlash(name), "/") {
		if seg == ".." {
			return "", fmt.Errorf("refusing %s in pack: escapes install dir", name)
		}
	}
	target := filepath.Join(root, filepath.Clean(name))
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing %s in pack: escapes install dir", name)
	}
	return target, nil
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
	verifyOpts := ociart.VerifyOptions{Identity: opts.ExpectedIdentity, CosignBin: opts.CosignBin}
	if verifyOpts.Identity == "" && repo != "" {
		verifyOpts.IdentityRegexp = ociart.IdentityRegexpForGitHubRepo(repo)
	}
	if verifyOpts.Identity == "" && verifyOpts.IdentityRegexp == "" {
		if opts.RequireSignature {
			return nil, errors.New("cannot determine signer identity from the artifact reference; pass --identity or --identity-regexp, or --no-verify to bypass verification")
		}
		fmt.Fprintln(progress, "  → signature verification SKIPPED (cannot determine signer identity)")
		return nil, nil
	}

	result, err := ociart.Verify(ctx, signedRef, verifyOpts)
	switch {
	case errors.Is(err, ociart.ErrCosignMissing):
		if opts.RequireSignature {
			return nil, fmt.Errorf("cosign is not on PATH; install cosign, or pass --no-verify to bypass verification: %w", err)
		}
		fmt.Fprintln(progress, "  → signature verification SKIPPED (cosign not on PATH)")
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("verifying signature: %w", err)
	}
	fmt.Fprintf(progress, "  → signature OK (signer=%s)\n", result.Identity)
	return result, nil
}

func writeLockEntry(path, framework string, pulled *ociart.PullResult, verify *ociart.VerifyResult, allowSignerChange bool) error {
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
	if prev := lf.LookupControlPack(framework); prev != nil && !allowSignerChange {
		if err := ociart.AssertSignerContinuity(prev.Signer, signer); err != nil {
			return err
		}
	}
	lf.UpsertControlPack(lockfile.LockedControlPack{
		Framework:   framework,
		Artifact:    pulled.Artifact,
		Version:     pulled.Tag,
		Digest:      pulled.Digest,
		Signer:      signer,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
	})
	return lockfile.Save(path, lf)
}

func defaultFrameworkFromArtifact(artifact string) string {
	base := artifact
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '/' {
			base = base[i+1:]
			break
		}
	}
	const prefix = "concord-controlpack-"
	if strings.HasPrefix(base, prefix) {
		return base[len(prefix):]
	}
	return ""
}
