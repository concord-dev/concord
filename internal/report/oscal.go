package report

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/google/uuid"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type OSCALRenderer struct{}

func (OSCALRenderer) Render(w io.Writer, findings []apiv1.Finding) (Summary, error) {
	s := Summarize(findings)
	now := time.Now().UTC().Format(time.RFC3339)

	results := buildOSCALResult(findings, now)

	doc := oscalEnvelope{
		AssessmentResults: oscalAssessmentResults{
			UUID: uuid.NewString(),
			Metadata: oscalMetadata{
				Title:        "Concord Automated Assessment Results",
				Published:    now,
				LastModified: now,
				Version:      "1.0",
				OscalVersion: "1.1.2",
			},
			ImportAp: oscalImportAp{Href: "#concord-assessment-plan"},
			Results:  []oscalResult{results},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return s, err
	}
	return s, nil
}

func buildOSCALResult(findings []apiv1.Finding, ts string) oscalResult {
	res := oscalResult{
		UUID:        uuid.NewString(),
		Title:       "Concord automated assessment",
		Description: "Findings produced by Concord controls evaluated against collected evidence.",
		Start:       ts,
		End:         ts,
	}

	for _, f := range findings {
		state := "satisfied"
		if f.Status == apiv1.StatusFail {
			state = "not-satisfied"
		} else if f.Status == apiv1.StatusError {
			state = "not-applicable"
		}

		var obsRefs []oscalObservationRef
		for _, msg := range f.Messages {
			obs := oscalObservation{
				UUID:        uuid.NewString(),
				Title:       f.ControlID + " observation",
				Description: msg,
				Methods:     []string{"TEST"},
				Collected:   ts,
			}
			res.Observations = append(res.Observations, obs)
			obsRefs = append(obsRefs, oscalObservationRef{ObservationUUID: obs.UUID})
		}

		res.Findings = append(res.Findings, oscalFinding{
			UUID:                uuid.NewString(),
			Title:               f.ControlID + " — " + f.Title,
			Description:         f.Title,
			Props:               buildMappingProps(f),
			Target:              oscalTarget{Type: "objective-id", TargetID: f.ControlID, Status: oscalStatus{State: state}},
			RelatedObservations: obsRefs,
		})
	}
	return res
}

func buildMappingProps(f apiv1.Finding) []oscalProp {
	props := []oscalProp{
		{Name: "framework", Value: f.Framework, NS: "https://concord.dev/ns"},
		{Name: "severity", Value: f.Severity, NS: "https://concord.dev/ns"},
	}
	if len(f.Mappings) == 0 {
		return props
	}
	keys := make([]string, 0, len(f.Mappings))
	for k := range f.Mappings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, framework := range keys {
		for _, controlRef := range f.Mappings[framework] {
			props = append(props, oscalProp{
				Name:  "mapped-control",
				Value: framework + ":" + controlRef,
				NS:    "https://concord.dev/ns/crosswalk",
			})
		}
	}
	return props
}

type oscalEnvelope struct {
	AssessmentResults oscalAssessmentResults `json:"assessment-results"`
}

type oscalAssessmentResults struct {
	UUID     string                 `json:"uuid"`
	Metadata oscalMetadata          `json:"metadata"`
	ImportAp oscalImportAp          `json:"import-ap"`
	Results  []oscalResult          `json:"results"`
}

type oscalMetadata struct {
	Title        string `json:"title"`
	Published    string `json:"published"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OscalVersion string `json:"oscal-version"`
}

type oscalImportAp struct {
	Href string `json:"href"`
}

type oscalResult struct {
	UUID         string             `json:"uuid"`
	Title        string             `json:"title"`
	Description  string             `json:"description"`
	Start        string             `json:"start"`
	End          string             `json:"end"`
	Findings     []oscalFinding     `json:"findings,omitempty"`
	Observations []oscalObservation `json:"observations,omitempty"`
}

type oscalFinding struct {
	UUID                string                `json:"uuid"`
	Title               string                `json:"title"`
	Description         string                `json:"description"`
	Props               []oscalProp           `json:"props,omitempty"`
	Target              oscalTarget           `json:"target"`
	RelatedObservations []oscalObservationRef `json:"related-observations,omitempty"`
}

type oscalProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	NS    string `json:"ns,omitempty"`
}

type oscalTarget struct {
	Type     string      `json:"type"`
	TargetID string      `json:"target-id"`
	Status   oscalStatus `json:"status"`
}

type oscalStatus struct {
	State string `json:"state"`
}

type oscalObservationRef struct {
	ObservationUUID string `json:"observation-uuid"`
}

type oscalObservation struct {
	UUID        string   `json:"uuid"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Methods     []string `json:"methods"`
	Collected   string   `json:"collected"`
}
