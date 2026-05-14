// Package config loads the per-repo concord.yaml file that declares user
// overrides for policy parameters and other tunables.
package config

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// Config is the schema of concord.yaml.
type Config struct {
	APIVersion string      `json:"apiVersion,omitempty"`
	Kind       string      `json:"kind,omitempty"`
	Metadata   Metadata    `json:"metadata,omitempty"`
	Controls   ControlsCfg `json:"controls,omitempty"`
}

// Metadata names the repo for human readers.
type Metadata struct {
	Name string `json:"name,omitempty"`
}

// ControlsCfg declares where controls live and per-control parameter overrides.
type ControlsCfg struct {
	Path   string                       `json:"path,omitempty"`
	Params map[string]map[string]any    `json:"params,omitempty"`
}

// Load reads concord.yaml at path. A missing file is not an error — an empty
// Config is returned so the rest of the CLI works on fresh repos.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &c, nil
}
