package controls

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type Loaded struct {
	Control apiv1.Control
	Path    string
}

func Load(root string) ([]Loaded, error) {
	var out []Loaded
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isControlFile(p) {
			return nil
		}
		c, err := LoadFile(p)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, Loaded{Control: c, Path: p})
		return nil
	})
	return out, err
}

func LoadFile(path string) (apiv1.Control, error) {
	var c apiv1.Control
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("yaml: %w", err)
	}
	if err := Validate(c); err != nil {
		return c, err
	}
	return c, nil
}

func isControlFile(p string) bool {
	if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
		return false
	}
	return true
}

func shouldSkipDir(name string) bool {
	switch name {
	case "policies", "tests", "fixtures", "_schema", ".git", "node_modules", "vendor":
		return true
	}
	return false
}
