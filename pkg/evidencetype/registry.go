package evidencetype

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"sigs.k8s.io/yaml"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// ErrNotFound is returned when no evidence type matches a lookup.
var ErrNotFound = errors.New("evidence type not found")

// Registry holds loaded evidence types indexed by id, with their compiled
// schemas cached for repeated validation.
type Registry struct {
	byID map[string][]entry
}

type entry struct {
	typ      apiv1.EvidenceType
	compiled *jsonschema.Schema
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{byID: make(map[string][]entry)}
}

// LoadDir walks each root, loads every EvidenceType artifact it finds, and
// returns a populated registry. Missing roots are skipped; files whose kind
// is not EvidenceType are ignored so the registry can share a tree with
// control YAMLs.
func LoadDir(roots ...string) (*Registry, error) {
	r := New()
	for _, root := range roots {
		if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if skipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !isYAML(p) {
				return nil
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if !isEvidenceTypeDoc(raw) {
				return nil
			}
			t, err := Parse(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			if err := r.Add(t); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Add validates, compiles, and indexes one evidence type. It rejects a
// second artifact with the same (id, version).
func (r *Registry) Add(t apiv1.EvidenceType) error {
	if err := Validate(t); err != nil {
		return err
	}
	for _, e := range r.byID[t.Metadata.ID] {
		if e.typ.Metadata.Version == t.Metadata.Version {
			return fmt.Errorf("duplicate evidence type %s@%s", t.Metadata.ID, t.Metadata.Version)
		}
	}
	sch, err := compileSchema(t.Metadata.ID, t.Spec.Schema)
	if err != nil {
		return err
	}
	versions := append(r.byID[t.Metadata.ID], entry{typ: t, compiled: sch})
	sort.Slice(versions, func(i, j int) bool {
		return compareVersion(versions[i].typ.Metadata.Version, versions[j].typ.Metadata.Version) < 0
	})
	r.byID[t.Metadata.ID] = versions
	return nil
}

// Get returns the evidence type with an exact (id, version).
func (r *Registry) Get(id, version string) (apiv1.EvidenceType, bool) {
	for _, e := range r.byID[id] {
		if e.typ.Metadata.Version == version {
			return e.typ, true
		}
	}
	return apiv1.EvidenceType{}, false
}

// Latest returns the highest-version evidence type for id.
func (r *Registry) Latest(id string) (apiv1.EvidenceType, bool) {
	versions := r.byID[id]
	if len(versions) == 0 {
		return apiv1.EvidenceType{}, false
	}
	return versions[len(versions)-1].typ, true
}

// Resolve returns the highest version satisfying ref's constraint.
func (r *Registry) Resolve(ref string) (apiv1.EvidenceType, error) {
	parsed, err := ParseRef(ref)
	if err != nil {
		return apiv1.EvidenceType{}, err
	}
	versions := r.byID[parsed.ID]
	for i := len(versions) - 1; i >= 0; i-- {
		if parsed.Matches(versions[i].typ.Metadata.Version) {
			return versions[i].typ, nil
		}
	}
	if len(versions) == 0 {
		return apiv1.EvidenceType{}, fmt.Errorf("%w: %s", ErrNotFound, parsed.ID)
	}
	return apiv1.EvidenceType{}, fmt.Errorf("%w: %s has no version matching %q", ErrNotFound, parsed.ID, parsed.Constraint)
}

// ValidatePayload validates a decoded evidence payload against the schema of
// the evidence type resolved from ref.
func (r *Registry) ValidatePayload(ref string, payload any) error {
	parsed, err := ParseRef(ref)
	if err != nil {
		return err
	}
	versions := r.byID[parsed.ID]
	for i := len(versions) - 1; i >= 0; i-- {
		if !parsed.Matches(versions[i].typ.Metadata.Version) {
			continue
		}
		return validateAgainst(versions[i].compiled, payload)
	}
	if len(versions) == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, parsed.ID)
	}
	return fmt.Errorf("%w: %s has no version matching %q", ErrNotFound, parsed.ID, parsed.Constraint)
}

// Has reports whether any version of id is registered.
func (r *Registry) Has(id string) bool {
	return len(r.byID[id]) > 0
}

// IDs returns every registered evidence-type id, sorted.
func (r *Registry) IDs() []string {
	out := make([]string, 0, len(r.byID))
	for id := range r.byID {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Len returns the number of distinct evidence-type ids.
func (r *Registry) Len() int { return len(r.byID) }

// validateAgainst normalizes the payload through jsonschema.UnmarshalJSON so
// numbers arrive as json.Number, then validates it against the schema.
func validateAgainst(sch *jsonschema.Schema, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("parsing payload json: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return err
	}
	return nil
}

func isEvidenceTypeDoc(raw []byte) bool {
	var head struct {
		Kind string `json:"kind"`
	}
	if err := yaml.Unmarshal(raw, &head); err != nil {
		return false
	}
	return head.Kind == Kind
}

func isYAML(p string) bool {
	return strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "policies", "tests", "fixtures":
		return true
	}
	return false
}
