// Package controlpacks installs, manages, and enumerates Concord
// control packs distributed as OCI artifacts.
package controlpacks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"
)

// PackFile is the metadata file at the root of every control pack.
const PackFile = "pack.yaml"

// Pack is the parsed pack.yaml document.
type Pack struct {
	APIVersion string       `json:"apiVersion" yaml:"apiVersion"`
	Kind       string       `json:"kind"       yaml:"kind"`
	Metadata   PackMetadata `json:"metadata"   yaml:"metadata"`
	Spec       PackSpec     `json:"spec"       yaml:"spec"`
}

// PackMetadata identifies the framework this pack implements.
type PackMetadata struct {
	ID             string `json:"id"                         yaml:"id"`
	Name           string `json:"name,omitempty"             yaml:"name,omitempty"`
	Version        string `json:"version"                    yaml:"version"`
	FrameworkLabel string `json:"framework_label,omitempty"  yaml:"framework_label,omitempty"`
}

// PackSpec declares the controls + evidence dependencies the pack provides.
type PackSpec struct {
	Controls        []string         `json:"controls,omitempty"         yaml:"controls,omitempty"`
	EvidenceSources []EvidenceSource `json:"evidence_sources,omitempty" yaml:"evidence_sources,omitempty"`
}

// EvidenceSource declares a semver constraint on a plugin source.
type EvidenceSource struct {
	Source  string `json:"source"  yaml:"source"`
	Version string `json:"version" yaml:"version"`
}

// ParsePack reads and validates a pack.yaml file.
func ParsePack(path string) (*Pack, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var p Pack
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validating %s: %w", path, err)
	}
	return &p, nil
}

// Validate enforces the pack.yaml schema invariants.
func (p *Pack) Validate() error {
	var errs []error
	if p.APIVersion == "" {
		errs = append(errs, errors.New("apiVersion is required"))
	}
	if p.Kind == "" {
		errs = append(errs, errors.New("kind is required"))
	}
	if p.Metadata.ID == "" {
		errs = append(errs, errors.New("metadata.id is required"))
	}
	if p.Metadata.Version == "" {
		errs = append(errs, errors.New("metadata.version is required"))
	}
	return errors.Join(errs...)
}

// EvidenceSourceNames returns the unique source names this pack declares it needs.
func (p *Pack) EvidenceSourceNames() []string {
	out := make([]string, 0, len(p.Spec.EvidenceSources))
	for _, e := range p.Spec.EvidenceSources {
		out = append(out, e.Source)
	}
	return out
}

// PackDir is the on-disk location for an installed pack.
func PackDir(installRoot, framework, version string) string {
	return filepath.Join(installRoot, framework, version)
}
