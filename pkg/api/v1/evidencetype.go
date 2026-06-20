package v1

import "encoding/json"

// EvidenceType is the versioned contract for one evidence payload shape.
// Its id is "source/type" (e.g. "okta/users_mfa"); a control's
// (source, type) pair resolves to it, and policies evaluate against the
// schema it declares.
type EvidenceType struct {
	APIVersion string               `json:"apiVersion" yaml:"apiVersion"`
	Kind       string               `json:"kind" yaml:"kind"`
	Metadata   EvidenceTypeMetadata `json:"metadata" yaml:"metadata"`
	Spec       EvidenceTypeSpec     `json:"spec" yaml:"spec"`
}

type EvidenceTypeMetadata struct {
	ID      string `json:"id" yaml:"id"`
	Version string `json:"version" yaml:"version"`
}

type EvidenceTypeSpec struct {
	Source        string          `json:"source" yaml:"source"`
	Description   string          `json:"description,omitempty" yaml:"description,omitempty"`
	Schema        json.RawMessage `json:"schema" yaml:"schema"`
	Compatibility string          `json:"compatibility,omitempty" yaml:"compatibility,omitempty"`
	Examples      []string        `json:"examples,omitempty" yaml:"examples,omitempty"`
}
