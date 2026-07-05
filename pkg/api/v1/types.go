package v1

import "time"

type Control struct {
	APIVersion string          `json:"apiVersion" yaml:"apiVersion"`
	Kind       string          `json:"kind" yaml:"kind"`
	Metadata   ControlMetadata `json:"metadata" yaml:"metadata"`
	Spec       ControlSpec     `json:"spec" yaml:"spec"`
}

type ControlMetadata struct {
	ID        string              `json:"id" yaml:"id"`
	Name      string              `json:"name" yaml:"name"`
	Title     string              `json:"title" yaml:"title"`
	Framework string              `json:"framework" yaml:"framework"`
	Version   string              `json:"version,omitempty" yaml:"version,omitempty"`
	Category  string              `json:"category,omitempty" yaml:"category,omitempty"`
	Severity  string              `json:"severity" yaml:"severity"`
	Tags      []string            `json:"tags,omitempty" yaml:"tags,omitempty"`
	Owners    []map[string]string `json:"owners,omitempty" yaml:"owners,omitempty"`
}

type ControlSpec struct {
	Description string              `json:"description" yaml:"description"`
	Rationale   string              `json:"rationale,omitempty" yaml:"rationale,omitempty"`
	Evidence    []EvidenceRef       `json:"evidence" yaml:"evidence"`
	Policy      PolicyRef           `json:"policy" yaml:"policy"`
	Remediation *Remediation        `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Mappings    map[string][]string `json:"mappings,omitempty" yaml:"mappings,omitempty"`
	Status      string              `json:"status,omitempty" yaml:"status,omitempty"`
	Blocking    bool                `json:"blocking,omitempty" yaml:"blocking,omitempty"`
}

type EvidenceRef struct {
	ID       string         `json:"id" yaml:"id"`
	Source   string         `json:"source" yaml:"source"`
	Type     string         `json:"type,omitempty" yaml:"type,omitempty"`
	Optional bool           `json:"optional,omitempty" yaml:"optional,omitempty"`
	Params   map[string]any `json:"params,omitempty" yaml:"params,omitempty"`
	Fixture  string         `json:"fixture,omitempty" yaml:"fixture,omitempty"`
}

type PolicyRef struct {
	Engine  string `json:"engine" yaml:"engine"`
	Package string `json:"package" yaml:"package"`
	File    string `json:"file" yaml:"file"`
	Query   string `json:"query,omitempty" yaml:"query,omitempty"`
}

type Remediation struct {
	Runbook         string `json:"runbook,omitempty" yaml:"runbook,omitempty"`
	AutoFix         bool   `json:"auto_fix,omitempty" yaml:"auto_fix,omitempty"`
	EstimatedEffort string `json:"estimated_effort,omitempty" yaml:"estimated_effort,omitempty"`
}

type FindingStatus string

const (
	StatusPass  FindingStatus = "pass"
	StatusFail  FindingStatus = "fail"
	StatusError FindingStatus = "error"
	StatusSkip  FindingStatus = "skip"
)

type Finding struct {
	ControlID string        `json:"control_id"`
	Title     string        `json:"title"`
	Framework string        `json:"framework"`
	Severity  string        `json:"severity"`
	Status    FindingStatus `json:"status"`
	Messages  []string      `json:"messages,omitempty"`
	Warnings  []string      `json:"warnings,omitempty"`
	// EvidenceFingerprint is a sha256 digest of the exact evidence the agent
	// evaluated to produce this finding (see FingerprintEvidence). It commits the
	// result to its inputs so the server records what the finding was based on
	// rather than an unverifiable claim. Empty when no evidence was collected
	// (e.g. an evaluation error).
	EvidenceFingerprint string              `json:"evidence_fingerprint,omitempty"`
	Mappings            map[string][]string `json:"mappings,omitempty"`
	EvaluatedAt         time.Time           `json:"evaluated_at"`
	DurationMs          int64               `json:"duration_ms"`
}

// ObservedAsset is an asset a collector reported during a run. Its JSON shape
// matches the platform's asset-ingest item; the agent posts a batch of these
// to /v1/orgs/{slug}/assets/ingest. Criticality 0 is omitted (unset).
type ObservedAsset struct {
	Source             string            `json:"source"`
	ExternalID         string            `json:"external_id"`
	Type               string            `json:"type"`
	Name               string            `json:"name"`
	ExternalIDs        map[string]string `json:"external_ids,omitempty"`
	Criticality        int               `json:"criticality,omitempty"`
	DataClassification string            `json:"data_classification,omitempty"`
	Environment        string            `json:"environment,omitempty"`
	Tags               []string          `json:"tags,omitempty"`
	Metadata           map[string]any    `json:"metadata,omitempty"`
}
