package report

import (
	"encoding/json"
	"io"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// JSONRenderer emits findings as a single JSON document on one line of stdout — friendly to pipes.
type JSONRenderer struct{}

// JSONReport is the top-level JSON shape Concord emits.
type JSONReport struct {
	Summary  Summary           `json:"summary"`
	Findings []apiv1.Finding   `json:"findings"`
}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, findings []apiv1.Finding) (Summary, error) {
	s := Summarize(findings)
	out := JSONReport{Summary: s, Findings: findings}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return s, err
	}
	return s, nil
}
