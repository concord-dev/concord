package config

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

type Config struct {
	APIVersion string      `json:"apiVersion,omitempty"`
	Kind       string      `json:"kind,omitempty"`
	Metadata   Metadata    `json:"metadata,omitempty"`
	Controls   ControlsCfg `json:"controls,omitempty"`
}

type Metadata struct {
	Name string `json:"name,omitempty"`
}

type ControlsCfg struct {
	Path   string                       `json:"path,omitempty"`
	Params map[string]map[string]any    `json:"params,omitempty"`
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
