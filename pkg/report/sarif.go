package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// SARIFRenderer emits SARIF 2.1.0 so `concord check`/`plan` output can be
// uploaded to GitHub code scanning (github/codeql-action/upload-sarif),
// surfacing failing controls as PR annotations and Security-tab alerts — the
// adoption wedge (assessment/29 P2-A). Output is a pure function of the findings
// (rules + results sorted, stable fingerprints) so re-runs diff cleanly.
type SARIFRenderer struct {
	// LocationURI is the repo-relative file results point at (GitHub needs a
	// location to annotate). Defaults to concord.yaml.
	LocationURI string
}

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

func (r SARIFRenderer) Render(w io.Writer, findings []apiv1.Finding) (Summary, error) {
	s := Summarize(findings)
	loc := r.LocationURI
	if loc == "" {
		loc = "concord.yaml"
	}
	doc := buildSARIF(findings, loc)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return s, err
	}
	return s, nil
}

// buildSARIF assembles the SARIF log: one rule per distinct control, and a
// result per problem (a failing/erroring control → error; any warnings →
// warning). Passing controls with no warnings produce no result, so a clean run
// is an empty findings list — exactly what a gate wants.
func buildSARIF(findings []apiv1.Finding, locationURI string) sarifLog {
	rules := map[string]sarifRule{}
	// Always a (possibly empty) array, never null — a clean run is valid SARIF
	// with zero results, which GitHub code scanning accepts and reads as "no
	// alerts". A nil slice would marshal to null and be rejected.
	results := []sarifResult{}
	for _, f := range findings {
		if _, ok := rules[f.ControlID]; !ok {
			rules[f.ControlID] = ruleFor(f)
		}
		if f.Status == apiv1.StatusFail || f.Status == apiv1.StatusError {
			results = append(results, resultFor(f, sarifError, problemMessage(f), locationURI))
		}
		if len(f.Warnings) > 0 {
			msg := f.Title + " — warnings: " + strings.Join(f.Warnings, "; ")
			results = append(results, resultFor(f, sarifWarning, withResource(f, msg), locationURI))
		}
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	sort.Slice(results, func(i, j int) bool {
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		if results[i].Level != results[j].Level {
			return results[i].Level < results[j].Level
		}
		return results[i].Message.Text < results[j].Message.Text
	})

	return sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Concord",
				InformationURI: "https://github.com/concord-dev/concord",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
}

func ruleFor(f apiv1.Finding) sarifRule {
	props := map[string]any{}
	if sev := securitySeverity(f.Severity); sev != "" {
		props["security-severity"] = sev
	}
	tags := []string{"compliance"}
	if f.Framework != "" {
		tags = append(tags, f.Framework)
	}
	tags = append(tags, sortedKeys(f.Mappings)...)
	props["tags"] = tags
	return sarifRule{
		ID:               f.ControlID,
		Name:             f.ControlID,
		ShortDescription: sarifText{Text: firstNonEmpty(f.Title, f.ControlID)},
		Properties:       props,
	}
}

func resultFor(f apiv1.Finding, level, message, locationURI string) sarifResult {
	return sarifResult{
		RuleID:  f.ControlID,
		Level:   level,
		Message: sarifText{Text: message},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: locationURI},
				Region:           &sarifRegion{StartLine: 1},
			},
		}},
		// Stable across runs so GitHub tracks the alert rather than re-opening it:
		// keyed by control + resource + level, not by the (changing) message.
		PartialFingerprints: map[string]string{
			"concord/v1": fingerprint(f.ControlID, f.ResourceID, level),
		},
	}
}

func problemMessage(f apiv1.Finding) string {
	msg := f.Title
	if f.Status == apiv1.StatusError {
		msg = "evaluation error: " + msg
	}
	if len(f.Messages) > 0 {
		msg += " — " + strings.Join(f.Messages, "; ")
	}
	return withResource(f, msg)
}

func withResource(f apiv1.Finding, msg string) string {
	if f.ResourceID != "" {
		return f.ControlID + " [" + f.ResourceID + "]: " + msg
	}
	return f.ControlID + ": " + msg
}

// securitySeverity maps a control severity onto GitHub's numeric
// security-severity scale (drives alert severity in the Security tab).
func securitySeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "9.8"
	case "high":
		return "8.1"
	case "medium", "moderate":
		return "5.5"
	case "low":
		return "3.1"
	default:
		return ""
	}
}

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func sortedKeys(m map[string][]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

const (
	sarifError   = "error"
	sarifWarning = "warning"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}
