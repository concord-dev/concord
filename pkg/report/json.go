package report

import (
	"encoding/json"
	"io"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type JSONRenderer struct{}

type JSONReport struct {
	Summary  Summary           `json:"summary"`
	Findings []apiv1.Finding   `json:"findings"`
}

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
