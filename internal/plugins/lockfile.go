package plugins

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"sigs.k8s.io/yaml"
)

// LockfilePath is the conventional path callers should pass to LoadLockfile / SaveLockfile.
const LockfilePath = "concord.lock"

// Lockfile records every installed plugin's pinned version, digest, and signer.
type Lockfile struct {
	APIVersion string             `json:"apiVersion" yaml:"apiVersion"`
	Kind       string             `json:"kind"       yaml:"kind"`
	Plugins    []LockedPlugin     `json:"plugins,omitempty" yaml:"plugins,omitempty"`
	UpdatedAt  *time.Time         `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

// LockedPlugin is a pinned plugin entry in the lockfile.
type LockedPlugin struct {
	Source      string `json:"source"            yaml:"source"`
	Artifact    string `json:"artifact"          yaml:"artifact"`
	Version     string `json:"version"           yaml:"version"`
	Digest      string `json:"digest"            yaml:"digest"`
	Signer      string `json:"signer,omitempty"  yaml:"signer,omitempty"`
	Platform    string `json:"platform,omitempty" yaml:"platform,omitempty"`
	InstalledAt string `json:"installed_at,omitempty" yaml:"installed_at,omitempty"`
}

// NewLockfile returns an empty lockfile with the current API version.
func NewLockfile() *Lockfile {
	return &Lockfile{APIVersion: "concord.dev/v1", Kind: "Lock"}
}

// LoadLockfile reads path. A missing file returns an empty lockfile, not an error.
func LoadLockfile(path string) (*Lockfile, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewLockfile(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	lf := NewLockfile()
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

// SaveLockfile writes the lockfile atomically (write to tmp, rename into place).
func SaveLockfile(path string, lf *Lockfile) error {
	lf.sortPlugins()
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

// Upsert replaces an existing entry with the same source, or appends a new one.
func (lf *Lockfile) Upsert(p LockedPlugin) {
	for i, existing := range lf.Plugins {
		if existing.Source == p.Source {
			lf.Plugins[i] = p
			return
		}
	}
	lf.Plugins = append(lf.Plugins, p)
}

// Remove deletes the entry for source, returning whether one was removed.
func (lf *Lockfile) Remove(source string) bool {
	for i, p := range lf.Plugins {
		if p.Source == source {
			lf.Plugins = append(lf.Plugins[:i], lf.Plugins[i+1:]...)
			return true
		}
	}
	return false
}

// Lookup returns the entry for source, or nil if not present.
func (lf *Lockfile) Lookup(source string) *LockedPlugin {
	for i, p := range lf.Plugins {
		if p.Source == source {
			return &lf.Plugins[i]
		}
	}
	return nil
}

func (lf *Lockfile) sortPlugins() {
	sort.Slice(lf.Plugins, func(i, j int) bool {
		return lf.Plugins[i].Source < lf.Plugins[j].Source
	})
}
