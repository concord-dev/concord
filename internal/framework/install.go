package framework

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/concord-dev/concord/internal/controlpacks"
	"github.com/concord-dev/concord/internal/lockfile"
	"github.com/concord-dev/concord/internal/ociart"
	"github.com/concord-dev/concord/internal/plugins"
)

// ApplyOptions tune Apply.
type ApplyOptions struct {
	LockfilePath      string
	PlainHTTP         bool
	RequireSignature  bool
	SkipSignature     bool
	AllowSignerChange bool
	CosignBin         string
	ProgressW         io.Writer
}

// Apply executes a Plan: installs every control pack and plugin in it,
// then writes the framework entries to the lockfile.
func Apply(ctx context.Context, plan *Plan, opts ApplyOptions) error {
	progress := opts.ProgressW
	if progress == nil {
		progress = io.Discard
	}
	if plan == nil {
		return errors.New("nil plan")
	}

	for _, p := range plan.ControlPacks {
		fmt.Fprintf(progress, "\n[control pack] %s %s (requested by %v)\n", p.Source, p.Version, p.RequestedBy)
		_, err := controlpacks.Install(ctx, p.Source+":"+p.Version, controlpacks.InstallOptions{
			LockfilePath:      opts.LockfilePath,
			PlainHTTP:         opts.PlainHTTP,
			RequireSignature:  opts.RequireSignature,
			SkipSignature:     opts.SkipSignature,
			AllowSignerChange: opts.AllowSignerChange,
			CosignBin:         opts.CosignBin,
			ProgressW:         progress,
		})
		if err != nil {
			return fmt.Errorf("installing control pack %s: %w", p.Source, err)
		}
	}

	for _, p := range plan.Plugins {
		fmt.Fprintf(progress, "\n[plugin] %s %s (requested by %v)\n", p.Source, p.Version, p.RequestedBy)
		_, err := plugins.Install(ctx, p.Source+":"+p.Version, plugins.InstallOptions{
			LockfilePath:      opts.LockfilePath,
			PlainHTTP:         opts.PlainHTTP,
			RequireSignature:  opts.RequireSignature,
			SkipSignature:     opts.SkipSignature,
			AllowSignerChange: opts.AllowSignerChange,
			CosignBin:         opts.CosignBin,
			ProgressW:         progress,
		})
		if err != nil {
			return fmt.Errorf("installing plugin %s: %w", p.Source, err)
		}
	}

	return writeFrameworkLockEntries(opts.LockfilePath, plan, opts.AllowSignerChange, opts.CosignBin, ctx)
}

// Remove drops a framework's entry from the lockfile. It does NOT garbage-collect
// transitively-installed control packs / plugins — those are removed by their own
// uninstall commands or by a subsequent solver+apply that no longer references them.
func Remove(frameworkID string, lockPath string) error {
	if lockPath == "" {
		lockPath = lockfile.Path
	}
	lf, err := lockfile.Load(lockPath)
	if err != nil {
		return err
	}
	if !lf.RemoveFramework(frameworkID) {
		return fmt.Errorf("no lockfile entry for framework %q", frameworkID)
	}
	return lockfile.Save(lockPath, lf)
}

func writeFrameworkLockEntries(path string, plan *Plan, allowSignerChange bool, cosignBin string, ctx context.Context) error {
	if path == "" {
		path = lockfile.Path
	}
	lf, err := lockfile.Load(path)
	if err != nil {
		return err
	}
	for _, f := range plan.Frameworks {
		signer := lookupFrameworkSigner(ctx, f.Source, f.Digest, cosignBin)
		if prev := lf.LookupFramework(f.ID); prev != nil && !allowSignerChange {
			if err := ociart.AssertSignerContinuity(prev.Signer, signer); err != nil {
				return err
			}
		}
		lf.UpsertFramework(lockfile.LockedFramework{
			ID:          f.ID,
			Artifact:    f.Source,
			Version:     f.Version,
			Digest:      f.Digest,
			Signer:      signer,
			InstalledAt: time.Now().UTC().Format(time.RFC3339),
		})
	}
	return lockfile.Save(path, lf)
}

func lookupFrameworkSigner(ctx context.Context, source, digest, cosignBin string) string {
	repo := ociart.DefaultGitHubRepoFromArtifact(source)
	if repo == "" {
		return ""
	}
	result, err := ociart.Verify(ctx, source+"@"+digest, ociart.VerifyOptions{
		IdentityRegexp: ociart.IdentityRegexpForGitHubRepo(repo),
		CosignBin:      cosignBin,
	})
	if err != nil {
		return ""
	}
	return result.Identity
}
