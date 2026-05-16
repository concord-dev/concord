// Package drift computes per-control status transitions between two runs.
// Pure functions — no I/O, no DB, no clock — so the detector is trivially
// testable and reusable from anywhere (server-side SubmitRun, the future
// `concord diff` CLI subcommand, batch backfill jobs).
//
// Detection rules:
//
//   - Compare each current finding to the same control_id in the prior set.
//   - If the prior had a status AND the current status differs, emit a
//     Transition with From = prior status, To = current status.
//   - Controls present in current but absent from prior are NOT emitted as
//     transitions — they're "new", not "drifted", and surfacing them as
//     drift would create a wall of noise on the first run after a controls
//     library upgrade.
//   - Controls present in prior but absent from current are NOT emitted
//     either — scope changes (a control was removed from the library) read
//     as drift events would be misleading.
//
// Both lists may be nil; nil + nil returns nil.
package drift

import (
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Transition is one control's status change between two runs. Rationale
// comes from the CURRENT finding (the "new state explanation"), since
// that's what an operator reading a webhook payload cares about.
type Transition struct {
	ControlID string              `json:"control_id"`
	From      apiv1.FindingStatus `json:"from"`
	To        apiv1.FindingStatus `json:"to"`
	Rationale string              `json:"rationale,omitempty"`
}

// Detect returns every (control_id) whose status changed between `prior`
// and `current`. Result order matches `current` traversal so consumers
// get a stable, deterministic stream.
func Detect(prior, current []apiv1.Finding) []Transition {
	if len(current) == 0 {
		return nil
	}
	priorByID := make(map[string]apiv1.FindingStatus, len(prior))
	for _, f := range prior {
		// If a control appears twice (shouldn't happen but defensive),
		// keep the FIRST seen status — last-write-wins on transition
		// detection would race with the order findings happen to be
		// serialized in.
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
			// The first policy-emitted message is the most useful one-
			// liner for a webhook payload ("Root account access key
			// detected"). Empty when the policy emitted nothing.
			Rationale: firstMessage(f.Messages),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// firstMessage returns the first non-empty entry of msgs. Lifted into its
// own helper so the detector body stays linear; trivial to expand later if
// we want richer rationale extraction (e.g. picking the highest-severity
// message when policies emit several).
func firstMessage(msgs []string) string {
	for _, m := range msgs {
		if m != "" {
			return m
		}
	}
	return ""
}

// Regressions is a convenience filter: only pass→fail (or pass→error)
// transitions, which are the "page someone" set. UI dashboards and
// webhook receivers can use this to skip the "fail→pass" remediation
// noise on a notify channel that's reserved for genuine bad news.
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
