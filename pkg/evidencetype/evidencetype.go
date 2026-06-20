// Package evidencetype loads and validates EvidenceType artifacts — the
// versioned JSON Schema contract for an evidence payload shape — and
// validates collected payloads or fixtures against them.
package evidencetype

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"sigs.k8s.io/yaml"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const (
	APIVersion = "concord.dev/v1"
	Kind       = "EvidenceType"
)

// knownCompatibility lists the accepted spec.compatibility values. Empty
// defaults to "backward" — additive minor versions only.
var knownCompatibility = map[string]bool{
	"":                    true,
	"backward":            true,
	"backward_transitive": true,
	"none":                true,
}

// Parse decodes one EvidenceType from YAML (or JSON) bytes and validates it.
func Parse(raw []byte) (apiv1.EvidenceType, error) {
	var t apiv1.EvidenceType
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return t, fmt.Errorf("yaml: %w", err)
	}
	if err := Validate(t); err != nil {
		return t, err
	}
	return t, nil
}

// Validate checks the structural fields and that the embedded schema
// compiles as JSON Schema.
func Validate(t apiv1.EvidenceType) error {
	var errs []error
	if t.APIVersion == "" {
		errs = append(errs, errors.New("apiVersion is required"))
	}
	if t.Kind != Kind {
		errs = append(errs, fmt.Errorf("kind must be %q, got %q", Kind, t.Kind))
	}
	if t.Metadata.ID == "" {
		errs = append(errs, errors.New("metadata.id is required"))
	}
	if t.Metadata.Version == "" {
		errs = append(errs, errors.New("metadata.version is required"))
	} else if !validSemver(t.Metadata.Version) {
		errs = append(errs, fmt.Errorf("metadata.version %q is not semver (want vMAJOR.MINOR.PATCH)", t.Metadata.Version))
	}
	if t.Spec.Source == "" {
		errs = append(errs, errors.New("spec.source is required"))
	}
	if !knownCompatibility[t.Spec.Compatibility] {
		errs = append(errs, fmt.Errorf("spec.compatibility %q is not one of backward|backward_transitive|none", t.Spec.Compatibility))
	}
	if len(bytes.TrimSpace(t.Spec.Schema)) == 0 {
		errs = append(errs, errors.New("spec.schema is required"))
	} else if _, err := compileSchema(t.Metadata.ID, t.Spec.Schema); err != nil {
		errs = append(errs, fmt.Errorf("spec.schema: %w", err))
	}
	return errors.Join(errs...)
}

// compileSchema compiles the raw JSON Schema. Numbers must flow through
// jsonschema.UnmarshalJSON (json.Number) rather than a float64-producing
// decoder, or integer keywords like minimum/maxItems misbehave.
func compileSchema(id string, raw []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parsing schema json: %w", err)
	}
	loc := schemaLoc(id)
	c := jsonschema.NewCompiler()
	if err := c.AddResource(loc, doc); err != nil {
		return nil, err
	}
	sch, err := c.Compile(loc)
	if err != nil {
		return nil, err
	}
	return sch, nil
}

func schemaLoc(id string) string {
	if id == "" {
		id = "anonymous"
	}
	return "mem:///evidence-type/" + id
}
