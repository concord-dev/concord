package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/policy"
	"github.com/concord-dev/concord/internal/report"
	"github.com/concord-dev/concord/internal/runner"
	"github.com/concord-dev/concord/internal/store"
)

// runJob is one queued evaluation request. The job carries enough identifying
// information to update the corresponding run row; the actual control library
// + registry are looked up off the Worker's Concord pointer.
type runJob struct {
	TenantID uuid.UUID
	RunID    uuid.UUID
}

// Worker is an in-process job pool. v0 runs jobs entirely within this process,
// which is fine for single-instance deployments. Multi-instance leadership +
// at-least-once delivery come with a DB-polled or pg-listen variant later.
type Worker struct {
	c       *Concord
	queue   chan runJob
	pool    int
	timeout time.Duration

	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}
	wg        sync.WaitGroup
}

// WorkerOpts tunes worker behavior. Zero values are sensible defaults.
type WorkerOpts struct {
	PoolSize  int           // number of goroutines pulling from the queue
	QueueSize int           // buffered channel capacity; full → Enqueue returns ErrQueueFull
	Timeout   time.Duration // per-job context budget
}

// ErrQueueFull is returned by Enqueue when the buffer is at capacity. Callers
// should surface this as 503 so the client backs off.
var ErrQueueFull = errors.New("run queue full")

// NewWorker constructs a Worker bound to the given Concord. Must call Start
// before enqueueing.
func NewWorker(c *Concord, opts WorkerOpts) *Worker {
	if opts.PoolSize <= 0 {
		opts.PoolSize = 4
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = 100
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Minute
	}
	return &Worker{
		c:       c,
		queue:   make(chan runJob, opts.QueueSize),
		pool:    opts.PoolSize,
		timeout: opts.Timeout,
		stop:    make(chan struct{}),
	}
}

// Start spins up PoolSize goroutines and returns immediately. Safe to call
// multiple times; only the first call has effect.
func (w *Worker) Start() {
	w.startOnce.Do(func() {
		for range w.pool {
			w.wg.Add(1)
			go w.loop()
		}
	})
}

// Enqueue submits a job. Returns ErrQueueFull if the buffer is at capacity.
func (w *Worker) Enqueue(job runJob) error {
	select {
	case w.queue <- job:
		return nil
	default:
		return ErrQueueFull
	}
}

// Shutdown stops the worker after every in-flight job finishes (or
// shutdownCtx fires). Subsequent Enqueue calls panic on a closed channel — by
// design, the caller should stop accepting work first.
func (w *Worker) Shutdown(shutdownCtx context.Context) error {
	w.stopOnce.Do(func() { close(w.queue) })

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-shutdownCtx.Done():
		return shutdownCtx.Err()
	}
}

func (w *Worker) loop() {
	defer w.wg.Done()
	for job := range w.queue {
		w.execute(job)
	}
}

// execute is the actual work of one job. Failures are recorded on the run
// row; we never panic out of the worker loop. Lifecycle events are emitted
// on the Concord bus so SSE subscribers see transitions in real time.
func (w *Worker) execute(job runJob) {
	ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
	defer cancel()

	if err := w.c.Store.MarkRunRunning(ctx, job.RunID); err != nil {
		fmt.Fprintf(os.Stderr, "worker: marking run %s running: %v\n", job.RunID, err)
		return
	}
	w.c.bus.Publish(Event{
		Kind: EventRunStarted, TenantID: job.TenantID, RunID: job.RunID,
		At: time.Now().UTC(), Status: string(store.RunRunning),
	})

	defer func() {
		if rec := recover(); rec != nil {
			msg := fmt.Sprintf("panic: %v", rec)
			_ = w.c.Store.FailRun(context.Background(), job.RunID, msg)
			w.c.bus.Publish(Event{
				Kind: EventRunFailed, TenantID: job.TenantID, RunID: job.RunID,
				At: time.Now().UTC(), Error: msg,
			})
			fmt.Fprintf(os.Stderr, "worker: %s\n", msg)
		}
	}()

	rn := runner.New(policy.New(), w.c.Registry).SetParams(w.c.Config.Controls.Params)
	findings := rn.RunAll(ctx, w.c.Controls)
	summary := report.Summarize(findings)

	summaryJSON, _ := json.Marshal(summary)
	findingsJSON, _ := json.Marshal(findings)
	if err := w.c.Store.CompleteRun(ctx, job.RunID, summaryJSON, findingsJSON); err != nil {
		_ = w.c.Store.FailRun(context.Background(), job.RunID, err.Error())
		w.c.bus.Publish(Event{
			Kind: EventRunFailed, TenantID: job.TenantID, RunID: job.RunID,
			At: time.Now().UTC(), Error: err.Error(),
		})
		fmt.Fprintf(os.Stderr, "worker: persisting run %s: %v\n", job.RunID, err)
		return
	}
	w.c.bus.Publish(Event{
		Kind: EventRunCompleted, TenantID: job.TenantID, RunID: job.RunID,
		At: time.Now().UTC(), Status: string(store.RunSucceeded), Summary: summaryJSON,
	})
}

// --- Test helpers ---

// waitForRun polls the store until run reaches a terminal state or ctx fires.
// Test-only; production callers should poll the HTTP endpoint instead.
func waitForRun(ctx context.Context, st *store.Store, tenantID, runID uuid.UUID) (store.Run, error) {
	for {
		r, err := st.GetRun(ctx, tenantID, runID)
		if err != nil {
			return store.Run{}, err
		}
		if r.Status == store.RunSucceeded || r.Status == store.RunFailed {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return store.Run{}, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
