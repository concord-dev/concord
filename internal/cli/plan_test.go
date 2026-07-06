package cli

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/watcher"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func TestPlanSymbol_ClassifiesEvents(t *testing.T) {
	cases := []struct {
		name    string
		event   watcher.Event
		wantSym string
	}{
		{"regression", watcher.Event{Reason: "regression", From: apiv1.StatusPass, To: apiv1.StatusFail}, "!"},
		{"eval error", watcher.Event{Reason: "evaluation error", From: apiv1.StatusPass, To: apiv1.StatusError}, "!"},
		{"remediated", watcher.Event{Reason: "remediated", From: apiv1.StatusFail, To: apiv1.StatusPass}, "~"},
		{"added", watcher.Event{Reason: "new control added since last run", To: apiv1.StatusPass}, "+"},
		{"removed", watcher.Event{Reason: "control removed since last run", From: apiv1.StatusPass, To: apiv1.FindingStatus("removed")}, "-"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sym, _ := planSymbol(tc.event)
			assert.Equal(t, tc.wantSym, sym)
		})
	}
}

func TestPlanTransition(t *testing.T) {
	assert.Equal(t, "pass", planTransition(watcher.Event{To: apiv1.StatusPass}))
	assert.Equal(t, "pass → fail", planTransition(watcher.Event{From: apiv1.StatusPass, To: apiv1.StatusFail}))
	assert.Equal(t, "pass → (removed)", planTransition(watcher.Event{From: apiv1.StatusPass, To: apiv1.FindingStatus("removed")}))
}

// A regression must be visible in the plan text and drive the failure line, so
// CI operators see why the gate tripped.
func TestRenderPlanText_ShowsRegression(t *testing.T) {
	base := []apiv1.Finding{{ControlID: "SOC2-CC8.1", Status: apiv1.StatusPass}}
	curr := []apiv1.Finding{{ControlID: "SOC2-CC8.1", Status: apiv1.StatusFail}}
	events := watcher.Diff(base, curr, time.Now().UTC())

	var buf bytes.Buffer
	renderPlanText(&buf, curr, events, "baseline.json", true)
	out := buf.String()

	assert.Contains(t, out, "! SOC2-CC8.1")
	assert.Contains(t, out, "pass → fail")
	assert.Contains(t, out, "1 to regress")
	assert.Contains(t, out, "would regress")
}

func TestRenderPlanText_NoBaselineHint(t *testing.T) {
	curr := []apiv1.Finding{{ControlID: "X", Status: apiv1.StatusPass}}
	events := watcher.Diff(nil, curr, time.Now().UTC())

	var buf bytes.Buffer
	renderPlanText(&buf, curr, events, "(no baseline)", false)
	out := buf.String()

	assert.Contains(t, out, "No baseline to compare against")
	assert.Contains(t, out, "+ X")
	assert.NotContains(t, out, "would regress")
}

func TestRenderPlanText_CleanPlan(t *testing.T) {
	same := []apiv1.Finding{{ControlID: "X", Status: apiv1.StatusPass}}
	events := watcher.Diff(same, same, time.Now().UTC())

	var buf bytes.Buffer
	renderPlanText(&buf, same, events, "baseline.json", true)
	assert.Contains(t, buf.String(), "No posture changes")
}

// serverBaseline must diff on the recorded evaluation status, falling back to
// the lifecycle status only when eval status is absent.
func TestServerBaseline_MapsEvaluationStatus(t *testing.T) {
	rows := []findingDTO{
		{ControlID: "A", Framework: "soc2", Severity: "high", CurrentEvaluationStatus: "fail", Status: "open"},
		{ControlID: "B", Framework: "soc2", CurrentEvaluationStatus: "", Status: "pass"},
	}
	got := mapDTOsToFindings(rows)
	require.Len(t, got, 2)
	assert.Equal(t, apiv1.StatusFail, got[0].Status)
	assert.Equal(t, "soc2", got[0].Framework)
	assert.Equal(t, apiv1.StatusPass, got[1].Status, "falls back to lifecycle status when eval status empty")
}

func TestNewPlanCmd_Wiring(t *testing.T) {
	cmd := newPlanCmd()
	assert.Equal(t, "plan", cmd.Name())
	for _, f := range []string{"baseline", "current", "from-server", "exit-on-regression", "controls", "framework"} {
		assert.NotNil(t, cmd.Flags().Lookup(f), "missing --%s", f)
	}
}

func TestNewApplyCmd_Wiring(t *testing.T) {
	cmd := newApplyCmd()
	assert.Equal(t, "apply", cmd.Name())
	for _, f := range []string{"findings", "fail-on-fail", "to", "controls", "key"} {
		assert.NotNil(t, cmd.Flags().Lookup(f), "missing --%s", f)
	}
}
