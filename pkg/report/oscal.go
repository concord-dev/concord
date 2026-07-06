package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// oscalNamespace anchors every deterministic (v5) UUID this renderer mints. It
// is itself derived deterministically so the value is self-documenting rather
// than a magic literal.
var oscalNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://concord.dev/oscal"))

type OSCALRenderer struct{}

// Render emits an OSCAL assessment-results document. The output is a pure
// function of the findings: UUIDs are content-seeded (UUIDv5) and timestamps
// are derived from the findings' EvaluatedAt window rather than wall-clock, so
// rendering the same findings twice is byte-identical. That lets teams commit
// OSCAL artifacts to Git and get clean, meaningful diffs — the whole point of
// compliance as code — instead of a full UUID/timestamp reshuffle every run.
func (OSCALRenderer) Render(w io.Writer, findings []apiv1.Finding) (Summary, error) {
	s := Summarize(findings)
	start, end := assessmentWindow(findings)
	published := end.Format(time.RFC3339)
	digest := findingsDigest(findings)

	results := buildOSCALResult(findings, start, end)
	results.UUID = detUUID("result:" + digest)

	doc := oscalEnvelope{
		AssessmentResults: oscalAssessmentResults{
			UUID: detUUID("assessment-results:" + digest),
			Metadata: oscalMetadata{
				Title:        "Concord Automated Assessment Results",
				Published:    published,
				LastModified: published,
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

func buildOSCALResult(findings []apiv1.Finding, start, end time.Time) oscalResult {
	res := oscalResult{
		Title:       "Concord automated assessment",
		Description: "Findings produced by Concord controls evaluated against collected evidence.",
		Start:       start.Format(time.RFC3339),
		End:         end.Format(time.RFC3339),
	}

	for _, f := range findings {
		state := "satisfied"
		if f.Status == apiv1.StatusFail {
			state = "not-satisfied"
		} else if f.Status == apiv1.StatusError {
			state = "not-applicable"
		}
		collected := f.EvaluatedAt.UTC().Format(time.RFC3339)
		findingKey := f.ControlID + "\x00" + f.ResourceID

		var obsRefs []oscalObservationRef
		for i, msg := range f.Messages {
			obs := oscalObservation{
				// Index guards against a finding repeating a message.
				UUID:        detUUID("observation:" + findingKey + "\x00" + strconv.Itoa(i) + "\x00" + msg),
				Title:       f.ControlID + " observation",
				Description: msg,
				Methods:     []string{"TEST"},
				Collected:   collected,
			}
			res.Observations = append(res.Observations, obs)
			obsRefs = append(obsRefs, oscalObservationRef{ObservationUUID: obs.UUID})
		}

		res.Findings = append(res.Findings, oscalFinding{
			// Seeded by (control, resource) alone so a finding keeps its UUID
			// even as sibling findings change — minimal diffs.
			UUID:                detUUID("finding:" + findingKey),
			Title:               f.ControlID + " — " + f.Title,
			Description:         f.Title,
			Props:               buildMappingProps(f),
			Target:              oscalTarget{Type: "objective-id", TargetID: f.ControlID, Status: oscalStatus{State: state}},
			RelatedObservations: obsRefs,
		})
	}
	return res
}

// detUUID returns a deterministic v5 UUID for a content key.
func detUUID(name string) string {
	return uuid.NewSHA1(oscalNamespace, []byte(name)).String()
}

// assessmentWindow is the [earliest, latest] EvaluatedAt across findings — the
// real evaluation window, and deterministic given the same findings. Zero
// EvaluatedAt values are ignored; an empty/all-zero set yields the zero time
// (which still formats to a stable RFC3339 string).
func assessmentWindow(findings []apiv1.Finding) (time.Time, time.Time) {
	var start, end time.Time
	for _, f := range findings {
		t := f.EvaluatedAt.UTC()
		if t.IsZero() {
			continue
		}
		if start.IsZero() || t.Before(start) {
			start = t
		}
		if t.After(end) {
			end = t
		}
	}
	return start, end
}

// findingsDigest is a stable sha256 over the finding identities + statuses, so
// the top-level assessment/result UUIDs are distinct per assessment content but
// identical when the content is.
func findingsDigest(findings []apiv1.Finding) string {
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, f.ControlID+"\x00"+f.ResourceID+"\x00"+string(f.Status))
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:])
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
	UUID     string        `json:"uuid"`
	Metadata oscalMetadata `json:"metadata"`
	ImportAp oscalImportAp `json:"import-ap"`
	Results  []oscalResult `json:"results"`
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
