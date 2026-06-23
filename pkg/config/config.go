package config

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

type Config struct {
	APIVersion string   `json:"apiVersion,omitempty"`
	Kind       string   `json:"kind,omitempty"`
	Metadata   Metadata `json:"metadata,omitempty"`
	// Project is the slug `concord push` targets when --project / env / profile
	// are all unset. Defaults to "default".
	Project    string                  `json:"project,omitempty"      yaml:"project,omitempty"`
	Controls   ControlsCfg             `json:"controls,omitempty"`
	Frameworks []FrameworkRef          `json:"frameworks,omitempty"  yaml:"frameworks,omitempty"`
	Sources    map[string]SourceConfig `json:"sources,omitempty"     yaml:"sources,omitempty"`
}

// SourceConfig overrides per-source behaviour. Today the only knob is
// Interval — used by `concord watch` to refresh each source on its own
// cadence instead of one global ticker.
type SourceConfig struct {
	Interval string `json:"interval,omitempty" yaml:"interval,omitempty"`
}

// FrameworkRef is one workspace-level framework dependency.
type FrameworkRef struct {
	Source  string `json:"source"            yaml:"source"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	Reason  string `json:"reason,omitempty"  yaml:"reason,omitempty"`
}

type Metadata struct {
	Name string `json:"name,omitempty"`
}

type ControlsCfg struct {
	Path   string                    `json:"path,omitempty"`
	Params map[string]map[string]any `json:"params,omitempty"`
}

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
