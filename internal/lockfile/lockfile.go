// Package lockfile reads and writes concord.lock, the per-workspace
// record of every pinned plugin, control pack, and framework artifact.
package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"sigs.k8s.io/yaml"
)

// Path is the conventional filename for the lockfile.
const Path = "concord.lock"

// Lockfile is the on-disk concord.lock document.
type Lockfile struct {
	APIVersion   string              `json:"apiVersion"   yaml:"apiVersion"`
	Kind         string              `json:"kind"         yaml:"kind"`
	Frameworks   []LockedFramework   `json:"frameworks,omitempty"    yaml:"frameworks,omitempty"`
	ControlPacks []LockedControlPack `json:"control_packs,omitempty" yaml:"control_packs,omitempty"`
	Plugins      []LockedPlugin      `json:"plugins,omitempty"       yaml:"plugins,omitempty"`
	UpdatedAt    *time.Time          `json:"updated_at,omitempty"    yaml:"updated_at,omitempty"`
}

// LockedFramework pins one installed framework manifest.
type LockedFramework struct {
	ID          string `json:"id"                     yaml:"id"`
	Artifact    string `json:"artifact"               yaml:"artifact"`
	Version     string `json:"version"                yaml:"version"`
	Digest      string `json:"digest"                 yaml:"digest"`
	Signer      string `json:"signer,omitempty"       yaml:"signer,omitempty"`
	InstalledAt string `json:"installed_at,omitempty" yaml:"installed_at,omitempty"`
}

// LockedPlugin pins one installed plugin binary.
type LockedPlugin struct {
	Source      string `json:"source"               yaml:"source"`
	Artifact    string `json:"artifact"             yaml:"artifact"`
	Version     string `json:"version"              yaml:"version"`
	Digest      string `json:"digest"               yaml:"digest"`
	Signer      string `json:"signer,omitempty"     yaml:"signer,omitempty"`
	Platform    string `json:"platform,omitempty"   yaml:"platform,omitempty"`
	InstalledAt string `json:"installed_at,omitempty" yaml:"installed_at,omitempty"`
}

// LockedControlPack pins one installed control pack.
type LockedControlPack struct {
	Framework   string `json:"framework"            yaml:"framework"`
	Artifact    string `json:"artifact"             yaml:"artifact"`
	Version     string `json:"version"              yaml:"version"`
	Digest      string `json:"digest"               yaml:"digest"`
	Signer      string `json:"signer,omitempty"     yaml:"signer,omitempty"`
	InstalledAt string `json:"installed_at,omitempty" yaml:"installed_at,omitempty"`
}

// New returns an empty lockfile stamped with the current API version.
func New() *Lockfile {
	return &Lockfile{APIVersion: "concord.dev/v1", Kind: "Lock"}
}

// Load reads path. A missing file returns an empty lockfile, not an error.
func Load(path string) (*Lockfile, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	lf := New()
	if err := yaml.Unmarshal(raw, lf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if lf.APIVersion == "" {
		lf.APIVersion = "concord.dev/v1"
	}
	if lf.Kind == "" {
		lf.Kind = "Lock"
	}
	return lf, nil
}

// Save writes the lockfile atomically (temp file + rename).
func Save(path string, lf *Lockfile) error {
	lf.sortEntries()
	now := time.Now().UTC()
	lf.UpdatedAt = &now

	raw, err := yaml.Marshal(lf)
	if err != nil {
		return fmt.Errorf("marshalling lockfile: %w", err)
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating lockfile dir: %w", err)
		}
	}

	tmp, err := os.CreateTemp(dir, ".concord.lock.*")
	if err != nil {
		return fmt.Errorf("creating temp lockfile: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp lockfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp lockfile: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming temp lockfile into place: %w", err)
	}
	return nil
}

// UpsertPlugin replaces an existing entry with the same source, or appends a new one.
func (lf *Lockfile) UpsertPlugin(p LockedPlugin) {
	for i, existing := range lf.Plugins {
		if existing.Source == p.Source {
			lf.Plugins[i] = p
			return
		}
	}
	lf.Plugins = append(lf.Plugins, p)
}

// RemovePlugin deletes the entry for source, returning whether one was removed.
func (lf *Lockfile) RemovePlugin(source string) bool {
	for i, p := range lf.Plugins {
		if p.Source == source {
			lf.Plugins = append(lf.Plugins[:i], lf.Plugins[i+1:]...)
			return true
		}
	}
	return false
}

// LookupPlugin returns the plugin entry for source, or nil if absent.
func (lf *Lockfile) LookupPlugin(source string) *LockedPlugin {
	for i, p := range lf.Plugins {
		if p.Source == source {
			return &lf.Plugins[i]
		}
	}
	return nil
}

// UpsertControlPack replaces an existing entry with the same framework, or appends a new one.
func (lf *Lockfile) UpsertControlPack(cp LockedControlPack) {
	for i, existing := range lf.ControlPacks {
		if existing.Framework == cp.Framework {
			lf.ControlPacks[i] = cp
			return
		}
	}
	lf.ControlPacks = append(lf.ControlPacks, cp)
}

// RemoveControlPack deletes the entry for framework, returning whether one was removed.
func (lf *Lockfile) RemoveControlPack(framework string) bool {
	for i, p := range lf.ControlPacks {
		if p.Framework == framework {
			lf.ControlPacks = append(lf.ControlPacks[:i], lf.ControlPacks[i+1:]...)
			return true
		}
	}
	return false
}

// LookupControlPack returns the pack entry for framework, or nil if absent.
func (lf *Lockfile) LookupControlPack(framework string) *LockedControlPack {
	for i, p := range lf.ControlPacks {
		if p.Framework == framework {
			return &lf.ControlPacks[i]
		}
	}
	return nil
}

// UpsertFramework replaces an existing entry with the same id, or appends a new one.
func (lf *Lockfile) UpsertFramework(f LockedFramework) {
	for i, existing := range lf.Frameworks {
		if existing.ID == f.ID {
			lf.Frameworks[i] = f
			return
		}
	}
	lf.Frameworks = append(lf.Frameworks, f)
}

// RemoveFramework deletes the entry for id, returning whether one was removed.
func (lf *Lockfile) RemoveFramework(id string) bool {
	for i, f := range lf.Frameworks {
		if f.ID == id {
			lf.Frameworks = append(lf.Frameworks[:i], lf.Frameworks[i+1:]...)
			return true
		}
	}
	return false
}

// LookupFramework returns the framework entry for id, or nil if absent.
func (lf *Lockfile) LookupFramework(id string) *LockedFramework {
	for i, f := range lf.Frameworks {
		if f.ID == id {
			return &lf.Frameworks[i]
		}
	}
	return nil
}

func (lf *Lockfile) sortEntries() {
	sort.Slice(lf.Frameworks, func(i, j int) bool { return lf.Frameworks[i].ID < lf.Frameworks[j].ID })
	sort.Slice(lf.Plugins, func(i, j int) bool { return lf.Plugins[i].Source < lf.Plugins[j].Source })
	sort.Slice(lf.ControlPacks, func(i, j int) bool { return lf.ControlPacks[i].Framework < lf.ControlPacks[j].Framework })
}
