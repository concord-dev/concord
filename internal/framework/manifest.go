// Package framework resolves Concord framework manifests into a concrete
// install plan: the union of control packs and plugins that satisfy a
// workspace's declared compliance frameworks, pinned at exact versions.
package framework

import (
	"errors"
	"fmt"

	"sigs.k8s.io/yaml"
)

// ManifestFile is the conventional filename inside a framework OCI artifact.
const ManifestFile = "manifest.yaml"

// Manifest is the parsed framework manifest stored at ghcr.io/concord-dev/concord-framework-<id>.
type Manifest struct {
	APIVersion string           `json:"apiVersion" yaml:"apiVersion"`
	Kind       string           `json:"kind"       yaml:"kind"`
	Metadata   ManifestMetadata `json:"metadata"   yaml:"metadata"`
	Spec       ManifestSpec     `json:"spec"       yaml:"spec"`
}

// ManifestMetadata describes the framework.
type ManifestMetadata struct {
	ID          string   `json:"id"                    yaml:"id"`
	Name        string   `json:"name,omitempty"        yaml:"name,omitempty"`
	Version     string   `json:"version"               yaml:"version"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Authors     []string `json:"authors,omitempty"     yaml:"authors,omitempty"`
}

// ManifestSpec declares what the framework needs to evaluate compliance.
type ManifestSpec struct {
	ControlPacks []Dependency `json:"control_packs,omitempty" yaml:"control_packs,omitempty"`
	Plugins      []Dependency `json:"plugins,omitempty"       yaml:"plugins,omitempty"`
	Extends      []Dependency `json:"extends,omitempty"       yaml:"extends,omitempty"`
}

// Dependency is one declared transitive artifact.
type Dependency struct {
	Source  string `json:"source"            yaml:"source"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	Reason  string `json:"reason,omitempty"  yaml:"reason,omitempty"`
}

// ParseManifest parses a manifest.yaml byte slice and validates it.
func ParseManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("validating manifest: %w", err)
	}
	return &m, nil
}

// Validate enforces the framework manifest schema invariants.
func (m *Manifest) Validate() error {
	var errs []error
	if m.APIVersion == "" {
		errs = append(errs, errors.New("apiVersion is required"))
	}
	if m.Kind == "" {
		errs = append(errs, errors.New("kind is required"))
	}
	if m.Metadata.ID == "" {
		errs = append(errs, errors.New("metadata.id is required"))
	}
	if m.Metadata.Version == "" {
		errs = append(errs, errors.New("metadata.version is required"))
	}
	for i, d := range m.Spec.ControlPacks {
		if d.Source == "" {
			errs = append(errs, fmt.Errorf("spec.control_packs[%d].source is required", i))
		}
	}
	for i, d := range m.Spec.Plugins {
		if d.Source == "" {
			errs = append(errs, fmt.Errorf("spec.plugins[%d].source is required", i))
		}
	}
	for i, d := range m.Spec.Extends {
		if d.Source == "" {
			errs = append(errs, fmt.Errorf("spec.extends[%d].source is required", i))
		}
	}
	return errors.Join(errs...)
}
