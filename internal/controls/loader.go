package controls

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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

// NeededSources returns the unique, sorted set of evidence.Source values
// referenced by loaded. The "file" source is omitted because it is always
// served in-process. Used by the plugin manager to lazy-spawn only what
// the current run will touch.
func NeededSources(loaded []Loaded) []string {
	set := make(map[string]struct{})
	for _, l := range loaded {
		for _, e := range l.Control.Spec.Evidence {
			if e.Source == "" || e.Source == "file" {
				continue
			}
			set[e.Source] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
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
