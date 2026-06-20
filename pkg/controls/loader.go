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
	return LoadFrom([]string{root})
}

// LoadFrom walks every root in turn and merges all control YAMLs found.
// Later roots can override earlier ones when the same metadata.id appears twice.
func LoadFrom(roots []string) ([]Loaded, error) {
	var out []Loaded
	seen := make(map[string]int)
	for _, root := range roots {
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
			raw, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			if !isControlDoc(raw) {
				// Sibling concord artifacts (EvidenceType, etc.) share the
				// tree; skip them rather than fail control loading.
				return nil
			}
			c, err := loadControl(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			if idx, ok := seen[c.Metadata.ID]; ok {
				out[idx] = Loaded{Control: c, Path: p}
				return nil
			}
			seen[c.Metadata.ID] = len(out)
			out = append(out, Loaded{Control: c, Path: p})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func LoadFile(path string) (apiv1.Control, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return apiv1.Control{}, err
	}
	return loadControl(raw)
}

func loadControl(raw []byte) (apiv1.Control, error) {
	var c apiv1.Control
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("yaml: %w", err)
	}
	if err := Validate(c); err != nil {
		return c, err
	}
	return c, nil
}

// isControlDoc reports whether a YAML document's kind is Control (or absent,
// for backward compatibility with kind-less files). A recognized sibling
// kind such as EvidenceType returns false so the walker skips it.
func isControlDoc(raw []byte) bool {
	var head struct {
		Kind string `json:"kind"`
	}
	if err := yaml.Unmarshal(raw, &head); err != nil {
		// Let the strict control parse surface the real error.
		return true
	}
	return head.Kind == "" || head.Kind == "Control"
}

// NeededSources returns the unique, sorted, non-file evidence sources referenced by loaded.
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
	case "policies", "tests", "fixtures", "_schema", "evidence-types", ".git", "node_modules", "vendor":
		return true
	}
	return false
}
