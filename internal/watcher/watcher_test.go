package watcher_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/watcher"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

var fixed = time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)

func TestDiff_PassToFailIsRegression(t *testing.T) {
	prev := []apiv1.Finding{{ControlID: "X", Title: "x", Status: apiv1.StatusPass}}
	curr := []apiv1.Finding{{ControlID: "X", Title: "x", Status: apiv1.StatusFail}}
	events := watcher.Diff(prev, curr, fixed)
	require.Len(t, events, 1)
	assert.Equal(t, "regression", events[0].Reason)
	assert.Equal(t, apiv1.StatusPass, events[0].From)
	assert.Equal(t, apiv1.StatusFail, events[0].To)
}

func TestDiff_FailToPassIsRemediated(t *testing.T) {
	prev := []apiv1.Finding{{ControlID: "X", Status: apiv1.StatusFail}}
	curr := []apiv1.Finding{{ControlID: "X", Status: apiv1.StatusPass}}
	events := watcher.Diff(prev, curr, fixed)
	require.Len(t, events, 1)
	assert.Equal(t, "remediated", events[0].Reason)
}

func TestDiff_UnchangedProducesNoEvent(t *testing.T) {
	prev := []apiv1.Finding{
		{ControlID: "X", Status: apiv1.StatusPass},
		{ControlID: "Y", Status: apiv1.StatusFail},
	}
	curr := []apiv1.Finding{
		{ControlID: "X", Status: apiv1.StatusPass},
		{ControlID: "Y", Status: apiv1.StatusFail},
	}
	assert.Empty(t, watcher.Diff(prev, curr, fixed))
}

func TestDiff_AddedControl(t *testing.T) {
	prev := []apiv1.Finding{{ControlID: "X", Status: apiv1.StatusPass}}
	curr := []apiv1.Finding{
		{ControlID: "X", Status: apiv1.StatusPass},
		{ControlID: "Y", Title: "new", Status: apiv1.StatusFail},
	}
	events := watcher.Diff(prev, curr, fixed)
	require.Len(t, events, 1)
	assert.Equal(t, "Y", events[0].ControlID)
	assert.Contains(t, events[0].Reason, "new control added")
}

func TestDiff_RemovedControl(t *testing.T) {
	prev := []apiv1.Finding{
		{ControlID: "X", Status: apiv1.StatusPass},
		{ControlID: "Y", Status: apiv1.StatusFail},
	}
	curr := []apiv1.Finding{{ControlID: "X", Status: apiv1.StatusPass}}
	events := watcher.Diff(prev, curr, fixed)
	require.Len(t, events, 1)
	assert.Equal(t, "Y", events[0].ControlID)
	assert.Contains(t, events[0].Reason, "removed")
}

func TestDiff_ErrorTransitions(t *testing.T) {
	prev := []apiv1.Finding{{ControlID: "X", Status: apiv1.StatusPass}}
	curr := []apiv1.Finding{{ControlID: "X", Status: apiv1.StatusError}}
	events := watcher.Diff(prev, curr, fixed)
	require.Len(t, events, 1)
	assert.Equal(t, "evaluation error", events[0].Reason)

	events = watcher.Diff(curr, prev, fixed)
	require.Len(t, events, 1)
	assert.Equal(t, "evaluation recovered", events[0].Reason)
}

func TestRun_Once_WritesFindingsAndEmitsEvents(t *testing.T) {
	dir := t.TempDir()
	prevPath := filepath.Join(dir, "last-run.json")
	prev := []apiv1.Finding{{ControlID: "X", Title: "x", Status: apiv1.StatusPass}}
	prevRaw, _ := json.Marshal(prev)
	require.NoError(t, os.WriteFile(prevPath, prevRaw, 0o644))

	curr := []apiv1.Finding{{ControlID: "X", Title: "x", Status: apiv1.StatusFail, Messages: []string{"boom"}}}
	var captured []watcher.Event
	w := watcher.New(
		func(ctx context.Context) ([]apiv1.Finding, error) { return curr, nil },
		watcher.Options{
			OutputDir: dir,
			Once:      true,
			Now:       func() time.Time { return fixed },
			EventSink: func(e watcher.Event) { captured = append(captured, e) },
			Logger:    os.NewFile(0, os.DevNull),
		},
	)
	require.NoError(t, w.Run(context.Background()))

	require.Len(t, captured, 1)
	assert.Equal(t, "X", captured[0].ControlID)
	assert.Equal(t, "regression", captured[0].Reason)

	// Verify last-run.json now reflects the failure.
	raw, err := os.ReadFile(prevPath)
	require.NoError(t, err)
	var got []apiv1.Finding
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Len(t, got, 1)
	assert.Equal(t, apiv1.StatusFail, got[0].Status)
}

func TestRun_FirstRunNoPrevState_EmitsNewControlEvents(t *testing.T) {
	dir := t.TempDir()
	curr := []apiv1.Finding{
		{ControlID: "X", Title: "x", Status: apiv1.StatusPass},
		{ControlID: "Y", Title: "y", Status: apiv1.StatusFail},
	}
	var events []watcher.Event
	w := watcher.New(
		func(ctx context.Context) ([]apiv1.Finding, error) { return curr, nil },
		watcher.Options{
			OutputDir: dir,
			Once:      true,
			Now:       func() time.Time { return fixed },
			EventSink: func(e watcher.Event) { events = append(events, e) },
			Logger:    os.NewFile(0, os.DevNull),
		},
	)
	require.NoError(t, w.Run(context.Background()))
	assert.Len(t, events, 2, "every control on first run is a 'new control added' event")
	for _, e := range events {
		assert.Contains(t, e.Reason, "new control added")
	}
}

func TestRun_RespectsContextCancellation(t *testing.T) {
	dir := t.TempDir()
	var calls int32
	w := watcher.New(
		func(ctx context.Context) ([]apiv1.Finding, error) {
			atomic.AddInt32(&calls, 1)
			return nil, nil
		},
		watcher.Options{
			OutputDir: dir,
			Interval:  50 * time.Millisecond,
			Now:       func() time.Time { return time.Now().UTC() },
			Logger:    os.NewFile(0, os.DevNull),
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not shut down after context cancel")
	}
	got := atomic.LoadInt32(&calls)
	assert.GreaterOrEqual(t, got, int32(2), "expected at least 2 runs in 120ms with 50ms interval")
}

func TestRun_CheckErrorIsLoggedButLoopContinues(t *testing.T) {
	dir := t.TempDir()
	var calls int32
	w := watcher.New(
		func(ctx context.Context) ([]apiv1.Finding, error) {
			atomic.AddInt32(&calls, 1)
			return nil, errors.New("collector down")
		},
		watcher.Options{
			OutputDir: dir,
			Once:      true,
			Now:       func() time.Time { return fixed },
			Logger:    os.NewFile(0, os.DevNull),
		},
	)
	err := w.Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "collector down")
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
}
