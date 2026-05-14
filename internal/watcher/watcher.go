// Package watcher runs Concord's compliance checks on a periodic schedule,
// persists each run's findings, and emits state-change events when a control
// transitions between pass/fail/error across runs.
package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// CheckFunc runs one evaluation cycle and returns the resulting findings.
// The watcher accepts this as a dependency so cmd-side wiring (controls
// loading, runner construction, collector registry) stays out of the watch loop.
type CheckFunc func(ctx context.Context) ([]apiv1.Finding, error)

// Event describes a control's status change between two consecutive runs.
type Event struct {
	ControlID string             `json:"control_id"`
	Title     string             `json:"title"`
	From      apiv1.FindingStatus `json:"from,omitempty"`
	To        apiv1.FindingStatus `json:"to"`
	Reason    string             `json:"reason"`
	At        time.Time          `json:"at"`
}

// Options configures a Watcher.
type Options struct {
	Interval  time.Duration
	OutputDir string
	Once      bool
	// Now is used in tests to inject a fixed time source.
	Now func() time.Time
	// EventSink receives state-change events as they happen. If nil, events
	// are written to stderr in a one-line text format.
	EventSink func(Event)
	// Logger receives operational status lines (start, sleep, errors).
	// If nil, defaults to stderr.
	Logger io.Writer
}

// Watcher executes CheckFunc on a schedule and emits state-change events.
type Watcher struct {
	check CheckFunc
	opts  Options
}

// New constructs a Watcher.
func New(check CheckFunc, opts Options) *Watcher {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.Logger == nil {
		opts.Logger = os.Stderr
	}
	if opts.EventSink == nil {
		opts.EventSink = func(e Event) {
			fmt.Fprintf(opts.Logger, "[%s] %s: %s → %s (%s)\n",
				e.At.Format(time.RFC3339), e.ControlID, e.From, e.To, e.Reason)
		}
	}
	if opts.OutputDir == "" {
		opts.OutputDir = ".concord"
	}
	return &Watcher{check: check, opts: opts}
}

// Run executes the watch loop until ctx is cancelled. When opts.Once is true,
// it runs a single iteration and returns.
func (w *Watcher) Run(ctx context.Context) error {
	if err := os.MkdirAll(w.opts.OutputDir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	prev, err := w.loadPrevious()
	if err != nil {
		fmt.Fprintf(w.opts.Logger, "warn: could not read previous run: %v\n", err)
	}

	for {
		findings, runErr := w.runOnce(ctx, prev)
		if runErr != nil {
			fmt.Fprintf(w.opts.Logger, "error: %v\n", runErr)
		} else {
			prev = findings
		}

		if w.opts.Once {
			return runErr
		}

		select {
		case <-ctx.Done():
			fmt.Fprintln(w.opts.Logger, "shutting down")
			return nil
		case <-time.After(w.opts.Interval):
		}
	}
}

func (w *Watcher) runOnce(ctx context.Context, prev []apiv1.Finding) ([]apiv1.Finding, error) {
	start := w.opts.Now()
	fmt.Fprintf(w.opts.Logger, "[%s] running checks…\n", start.Format(time.RFC3339))

	findings, err := w.check(ctx)
	if err != nil {
		return nil, fmt.Errorf("check failed: %w", err)
	}

	events := Diff(prev, findings, w.opts.Now())
	for _, e := range events {
		w.opts.EventSink(e)
	}

	if writeErr := w.writeFindings(findings); writeErr != nil {
		return findings, fmt.Errorf("persisting findings: %w", writeErr)
	}

	dur := w.opts.Now().Sub(start)
	fmt.Fprintf(w.opts.Logger, "  → %d control(s) evaluated in %s; %d state change(s)\n",
		len(findings), dur.Round(time.Millisecond), len(events))
	return findings, nil
}

// Diff returns events for every control whose status changed between prev and
// curr, plus added/removed controls. Both slices are matched by ControlID.
func Diff(prev, curr []apiv1.Finding, at time.Time) []Event {
	prevByID := indexByID(prev)
	currByID := indexByID(curr)

	var events []Event
	for id, c := range currByID {
		p, hadBefore := prevByID[id]
		switch {
		case !hadBefore:
			events = append(events, Event{
				ControlID: id, Title: c.Title, To: c.Status,
				Reason: "new control added since last run", At: at,
			})
		case p.Status != c.Status:
			events = append(events, Event{
				ControlID: id, Title: c.Title,
				From: p.Status, To: c.Status,
				Reason: changeReason(p.Status, c.Status), At: at,
			})
		}
	}
	for id, p := range prevByID {
		if _, ok := currByID[id]; !ok {
			events = append(events, Event{
				ControlID: id, Title: p.Title,
				From: p.Status, To: apiv1.FindingStatus("removed"),
				Reason: "control removed since last run", At: at,
			})
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].ControlID < events[j].ControlID })
	return events
}

func changeReason(from, to apiv1.FindingStatus) string {
	switch {
	case from == apiv1.StatusPass && to == apiv1.StatusFail:
		return "regression"
	case from == apiv1.StatusFail && to == apiv1.StatusPass:
		return "remediated"
	case to == apiv1.StatusError:
		return "evaluation error"
	case from == apiv1.StatusError:
		return "evaluation recovered"
	}
	return "status changed"
}

func indexByID(f []apiv1.Finding) map[string]apiv1.Finding {
	out := make(map[string]apiv1.Finding, len(f))
	for _, x := range f {
		out[x.ControlID] = x
	}
	return out
}

// LastRunPath returns the canonical location of the most recent findings file
// inside outputDir.
func LastRunPath(outputDir string) string {
	return filepath.Join(outputDir, "last-run.json")
}

func (w *Watcher) loadPrevious() ([]apiv1.Finding, error) {
	path := LastRunPath(w.opts.OutputDir)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var findings []apiv1.Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return findings, nil
}

func (w *Watcher) writeFindings(findings []apiv1.Finding) error {
	path := LastRunPath(w.opts.OutputDir)
	tmp := path + ".tmp"
	raw, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
