package bg

import (
	"context"
	"log/slog"
	"sync"
)

type Runner struct {
	wg sync.WaitGroup
}

func New() *Runner { return &Runner{} }

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
