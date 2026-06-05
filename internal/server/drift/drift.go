package drift

import (
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type Transition struct {
	ControlID string              `json:"control_id"`
	From      apiv1.FindingStatus `json:"from"`
	To        apiv1.FindingStatus `json:"to"`
	Rationale string              `json:"rationale,omitempty"`
}

func Detect(prior, current []apiv1.Finding) []Transition {
	if len(current) == 0 {
		return nil
	}
	priorByID := make(map[string]apiv1.FindingStatus, len(prior))
	for _, f := range prior {
		if _, seen := priorByID[f.ControlID]; !seen {
			priorByID[f.ControlID] = f.Status
		}
	}
	out := make([]Transition, 0)
	seen := make(map[string]struct{}, len(current))
	for _, f := range current {
		if _, dup := seen[f.ControlID]; dup {
			continue // de-dupe same as prior loop
		}
		seen[f.ControlID] = struct{}{}
		before, ok := priorByID[f.ControlID]
		if !ok {
			continue // new control — not drift
		}
		if before == f.Status {
			continue // stable
		}
		out = append(out, Transition{
			ControlID: f.ControlID,
			From:      before,
			To:        f.Status,
			Rationale: firstMessage(f.Messages),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstMessage(msgs []string) string {
	for _, m := range msgs {
		if m != "" {
			return m
		}
	}
	return ""
}

func Regressions(ts []Transition) []Transition {
	out := make([]Transition, 0, len(ts))
	for _, t := range ts {
		if t.From == apiv1.StatusPass &&
			(t.To == apiv1.StatusFail || t.To == apiv1.StatusError) {
			out = append(out, t)
		}
	}
	return out
}
