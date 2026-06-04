// Package bg is a tiny tracked-goroutine helper. One Runner per process
// owns a WaitGroup; callers fire-and-forget background work via Runner.Go
// (instead of bare `go fn()`), and shutdown calls Runner.Wait to drain.
//
// Concord uses this for every "best-effort, off the request goroutine"
// side effect — webhook delivery, transactional email, bus drops — so a
// SIGTERM during a deploy doesn't drop notifications mid-flight.
package bg

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// Runner is the tracked-goroutine surface. Construct via New; the zero
// value is also usable, but tests prefer New so a per-test Runner doesn't
// leak across cases.
type Runner struct {
	wg       sync.WaitGroup
	shutting atomic.Bool
}

// New returns an empty Runner.
func New() *Runner { return &Runner{} }

// Go schedules fn on a tracked goroutine. After Wait has been called, Go
// is a no-op — late-arriving work submitted during shutdown is dropped
// (and slog-warned) so we don't extend the shutdown indefinitely.
//
// Panics inside fn are recovered and slog-logged with a stack so a
// misbehaving background task can't crash the whole process; the
// recovery is intentionally permissive because Go calls happen on the
// hot path of HTTP handlers and crashing the server because a single
// webhook receiver returned bad TLS would be a denial-of-service vector.
func (r *Runner) Go(fn func()) {
	if r.shutting.Load() {
		slog.Warn("bg: refusing to spawn background work — shutdown already in progress")
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("bg: background task panic recovered",
					slog.Any("recovered", rec))
			}
		}()
		fn()
	}()
}

// Wait blocks until every Go-scheduled task has finished, or ctx expires
// (whichever comes first). After Wait returns, the Runner refuses new
// work — see Go's docstring. Safe to call Wait multiple times; the
// shutting flag is only flipped once.
//
// Returns nil on clean drain, ctx.Err() when the context deadline
// trips. Callers should treat ctx.Err() as "some tasks still in
// flight; their writes may not have hit the wire" and log accordingly.
func (r *Runner) Wait(ctx context.Context) error {
	r.shutting.Store(true)
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
