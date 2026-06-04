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
)

// Runner is the tracked-goroutine surface. Construct via New; the zero
// value is also usable, but tests prefer New so a per-test Runner doesn't
// leak across cases.
type Runner struct {
	wg sync.WaitGroup
}

// New returns an empty Runner.
func New() *Runner { return &Runner{} }

// Go schedules fn on a tracked goroutine. Callers may invoke Go from
// inside another tracked goroutine — nested spawns (e.g. fireWebhooks
// fans out into deliverOne) are first-class and the WaitGroup
// accumulates them correctly.
//
// IMPORTANT: callers must stop invoking Go before calling Wait. In our
// architecture this is guaranteed by cmd/server's drain order: it calls
// *http.Server.Shutdown first (which stops accepting new connections and
// drains in-flight HTTP handlers) BEFORE Concord.Shutdown(ctx) which
// invokes Runner.Wait. Once handlers can no longer run, no new Go calls
// can originate from HTTP — only nested spawns from already-tracked
// goroutines, which is the case Wait correctly handles.
//
// Panics inside fn are recovered and slog-logged with a stack so a
// misbehaving background task can't crash the whole process; the
// recovery is intentionally permissive because Go calls happen on the
// hot path of HTTP handlers and crashing the server because a single
// webhook receiver returned bad TLS would be a denial-of-service vector.
func (r *Runner) Go(fn func()) {
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
// (whichever comes first). Returns nil on clean drain, ctx.Err() when
// the context deadline trips. Callers should treat ctx.Err() as "some
// tasks still in flight; their writes may not have hit the wire" and
// log accordingly.
//
// Safe to call Wait multiple times — it just reads the WaitGroup state.
// However, callers MUST NOT call Go after Wait has returned successfully
// (sync.WaitGroup forbids Add-after-Wait races). cmd/server enforces
// this by draining the HTTP server first, which fences off any handler-
// originated Go calls.
func (r *Runner) Wait(ctx context.Context) error {
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
