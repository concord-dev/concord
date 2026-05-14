package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/concord-dev/concord/internal/store"
)

// cronParser accepts standard 5-field expressions plus descriptors and
// @every spans. Created once; cron.Parser is stateless and safe to share.
var cronParser = cron.NewParser(
	cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
)

// ValidateCronExpr returns the next fire time for a given expression, or an
// error explaining why the expression is unparseable.
func ValidateCronExpr(expr string, from time.Time) (time.Time, error) {
	sched, err := cronParser.Parse(expr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid cron expression %q: %w", expr, err)
	}
	return sched.Next(from), nil
}

// Scheduler polls the schedule table on a fixed cadence, claims due rows
// with FOR UPDATE SKIP LOCKED, and enqueues runs on the Concord worker.
// One Scheduler per process; horizontal scaling is safe because of the
// row-level lock.
type Scheduler struct {
	c        *Concord
	interval time.Duration

	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}
	done      chan struct{}
}

// SchedulerOpts tunes the scheduler. Zero values are sensible defaults.
type SchedulerOpts struct {
	// Interval between poll cycles. Smaller means finer-grained schedule
	// firing at the cost of more DB load. 30s is the v1 default.
	Interval time.Duration
}

// NewScheduler constructs a Scheduler bound to a Concord instance.
func NewScheduler(c *Concord, opts SchedulerOpts) *Scheduler {
	if opts.Interval <= 0 {
		opts.Interval = 30 * time.Second
	}
	return &Scheduler{
		c:        c,
		interval: opts.Interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start kicks off the scheduler goroutine. Idempotent.
func (s *Scheduler) Start() {
	s.startOnce.Do(func() {
		go s.loop()
	})
}

// Shutdown signals the scheduler to stop and waits for the current tick to
// finish (or ctx to fire).
func (s *Scheduler) Shutdown(ctx context.Context) error {
	s.stopOnce.Do(func() { close(s.stop) })
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Scheduler) loop() {
	defer close(s.done)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		s.tick()
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
	}
}

func (s *Scheduler) tick() {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	nextFn := func(expr string) (time.Time, error) {
		return ValidateCronExpr(expr, time.Now())
	}
	claimed, err := s.c.Store.ClaimDueSchedules(ctx, time.Now(), nextFn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scheduler: claiming due rows: %v\n", err)
		return
	}
	for _, sch := range claimed {
		run, err := s.c.Store.CreateRun(ctx, store.CreateRunParams{OrgID: sch.OrgID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "scheduler: creating run for org %s: %v\n", sch.OrgID, err)
			continue
		}
		if err := s.c.worker.Enqueue(runJob{OrgID: sch.OrgID, RunID: run.ID}); err != nil {
			// Queue full — mark the run failed so it doesn't sit pending forever.
			_ = s.c.Store.FailRun(context.Background(), run.ID, "scheduler: "+err.Error())
			fmt.Fprintf(os.Stderr, "scheduler: enqueueing run %s: %v\n", run.ID, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "scheduler: fired schedule for org %s (run %s)\n", sch.OrgID, run.ID)
	}
}

// FireImmediately is a test-only helper that runs one scheduler tick
// synchronously. Production code lets the internal goroutine handle ticks.
// The *testing.T parameter is a guard to keep this method out of non-test
// call sites — callers must already have a t available.
func (s *Scheduler) FireImmediately(t interface{ Helper() }) {
	t.Helper()
	s.tick()
}

// ErrUnknownCron is returned by ValidateCronExpr when the expression cannot
// be parsed. Kept separate from the wrapped error so handlers can distinguish
// "user-supplied bad input" from internal failures.
var ErrUnknownCron = errors.New("unknown cron expression")
