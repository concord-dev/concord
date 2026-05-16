package drift_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/concord-dev/concord/internal/server/drift"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// f is shorthand for building a Finding with just the fields the detector
// inspects. The `msg` slot lands in Messages — the detector pulls the first
// non-empty entry into Transition.Rationale at boundary time.
func f(id string, st apiv1.FindingStatus, msg string) apiv1.Finding {
	out := apiv1.Finding{ControlID: id, Status: st}
	if msg != "" {
		out.Messages = []string{msg}
	}
	return out
}

func TestDetect_NilOrEmptyInputsReturnNil(t *testing.T) {
	assert.Nil(t, drift.Detect(nil, nil))
	assert.Nil(t, drift.Detect(nil, []apiv1.Finding{}))
	assert.Nil(t, drift.Detect([]apiv1.Finding{}, []apiv1.Finding{}))
}

func TestDetect_FirstRunHasNoPriorAndYieldsNoDrift(t *testing.T) {
	// First-ever run: 50 fresh controls, all with status. Surfacing them as
	// drift would be a wall of noise the user has to dismiss.
	current := []apiv1.Finding{
		f("a", apiv1.StatusPass, ""),
		f("b", apiv1.StatusFail, "bad config"),
	}
	got := drift.Detect(nil, current)
	assert.Empty(t, got,
		"first run (no prior) must NOT generate drift — that's the noise we're trying to avoid")
}

func TestDetect_NoTransitionsWhenStable(t *testing.T) {
	prior := []apiv1.Finding{f("a", apiv1.StatusPass, ""), f("b", apiv1.StatusFail, "x")}
	current := []apiv1.Finding{f("a", apiv1.StatusPass, ""), f("b", apiv1.StatusFail, "x")}
	assert.Empty(t, drift.Detect(prior, current))
}

func TestDetect_PassToFailIsEmitted(t *testing.T) {
	prior := []apiv1.Finding{f("a", apiv1.StatusPass, "")}
	current := []apiv1.Finding{f("a", apiv1.StatusFail, "key found")}
	got := drift.Detect(prior, current)
	if assert.Len(t, got, 1) {
		assert.Equal(t, "a", got[0].ControlID)
		assert.Equal(t, apiv1.StatusPass, got[0].From)
		assert.Equal(t, apiv1.StatusFail, got[0].To)
		assert.Equal(t, "key found", got[0].Rationale,
			"rationale must come from the CURRENT finding — that's what the operator needs to act on")
	}
}

func TestDetect_FailToPassIsEmittedAsRemediation(t *testing.T) {
	prior := []apiv1.Finding{f("a", apiv1.StatusFail, "key found")}
	current := []apiv1.Finding{f("a", apiv1.StatusPass, "")}
	got := drift.Detect(prior, current)
	if assert.Len(t, got, 1) {
		assert.Equal(t, apiv1.StatusFail, got[0].From)
		assert.Equal(t, apiv1.StatusPass, got[0].To)
	}
}

func TestDetect_NewControlsAreNotDrift(t *testing.T) {
	// A new control showing up after a library upgrade must NOT be
	// reported as drift — it's a scope addition, not a regression.
	prior := []apiv1.Finding{f("a", apiv1.StatusPass, "")}
	current := []apiv1.Finding{
		f("a", apiv1.StatusPass, ""),
		f("b-new", apiv1.StatusFail, "anything"),
	}
	assert.Empty(t, drift.Detect(prior, current))
}

func TestDetect_DisappearedControlsAreNotDrift(t *testing.T) {
	// Scope shrunk (controls removed from library). Surface as drift would
	// imply someone broke a control they actually intentionally retired.
	prior := []apiv1.Finding{
		f("a", apiv1.StatusPass, ""),
		f("b-retired", apiv1.StatusFail, "x"),
	}
	current := []apiv1.Finding{f("a", apiv1.StatusPass, "")}
	assert.Empty(t, drift.Detect(prior, current))
}

func TestDetect_MultipleTransitionsArePreserved(t *testing.T) {
	prior := []apiv1.Finding{
		f("a", apiv1.StatusPass, ""),
		f("b", apiv1.StatusFail, "x"),
		f("c", apiv1.StatusPass, ""),
	}
	current := []apiv1.Finding{
		f("a", apiv1.StatusFail, "regression"), // pass → fail
		f("b", apiv1.StatusPass, ""),           // fail → pass
		f("c", apiv1.StatusPass, ""),           // stable
	}
	got := drift.Detect(prior, current)
	assert.Len(t, got, 2, "exactly one transition per changed control")
}

func TestRegressions_FiltersToOnlyPassToFailOrError(t *testing.T) {
	ts := []drift.Transition{
		{ControlID: "a", From: apiv1.StatusPass, To: apiv1.StatusFail},
		{ControlID: "b", From: apiv1.StatusFail, To: apiv1.StatusPass},  // remediation — excluded
		{ControlID: "c", From: apiv1.StatusPass, To: apiv1.StatusError}, // included
		{ControlID: "d", From: apiv1.StatusSkip, To: apiv1.StatusFail},  // skip→fail — excluded (not a regression)
	}
	regs := drift.Regressions(ts)
	assert.Len(t, regs, 2)
	ids := []string{regs[0].ControlID, regs[1].ControlID}
	assert.ElementsMatch(t, []string{"a", "c"}, ids)
}
