// Package v1 defines the public Concord API types.
package v1

import "time"

// Control is a versioned, declarative compliance control.
type Control struct {
	APIVersion string          `json:"apiVersion" yaml:"apiVersion"`
	Kind       string          `json:"kind" yaml:"kind"`
	Metadata   ControlMetadata `json:"metadata" yaml:"metadata"`
	Spec       ControlSpec     `json:"spec" yaml:"spec"`
}

// ControlMetadata describes a control's identity and lifecycle.
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

// ControlSpec is the executable contents of a control.
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

// EvidenceRef declares one piece of evidence a control needs.
type EvidenceRef struct {
	ID       string         `json:"id" yaml:"id"`
	Source   string         `json:"source" yaml:"source"`
	Type     string         `json:"type,omitempty" yaml:"type,omitempty"`
	Optional bool           `json:"optional,omitempty" yaml:"optional,omitempty"`
	Params   map[string]any `json:"params,omitempty" yaml:"params,omitempty"`
	Fixture  string         `json:"fixture,omitempty" yaml:"fixture,omitempty"`
}

// PolicyRef points at the Rego policy that evaluates the control.
type PolicyRef struct {
	Engine  string `json:"engine" yaml:"engine"`
	Package string `json:"package" yaml:"package"`
	File    string `json:"file" yaml:"file"`
	Query   string `json:"query,omitempty" yaml:"query,omitempty"`
}

// Remediation describes how to fix a failing control.
type Remediation struct {
	Runbook         string `json:"runbook,omitempty" yaml:"runbook,omitempty"`
	AutoFix         bool   `json:"auto_fix,omitempty" yaml:"auto_fix,omitempty"`
	EstimatedEffort string `json:"estimated_effort,omitempty" yaml:"estimated_effort,omitempty"`
}

// FindingStatus is the outcome of evaluating a control.
type FindingStatus string

const (
	StatusPass  FindingStatus = "pass"
	StatusFail  FindingStatus = "fail"
	StatusError FindingStatus = "error"
	StatusSkip  FindingStatus = "skip"
)

// Finding is the result of evaluating a single control.
type Finding struct {
	ControlID   string              `json:"control_id"`
	Title       string              `json:"title"`
	Framework   string              `json:"framework"`
	Severity    string              `json:"severity"`
	Status      FindingStatus       `json:"status"`
	Messages    []string            `json:"messages,omitempty"`
	Warnings    []string            `json:"warnings,omitempty"`
	Mappings    map[string][]string `json:"mappings,omitempty"`
	EvaluatedAt time.Time           `json:"evaluated_at"`
	DurationMs  int64               `json:"duration_ms"`
}
