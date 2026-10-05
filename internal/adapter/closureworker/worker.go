package closureworker

import (
	"context"
	"errors"
	"sync"
	"time"
)

type Tasks interface{ Tick(context.Context) error }

// Worker participates in the server lifecycle. Runtime construction never starts
// a detached task; Stop cancels in-flight Mongo/RPC work and waits for completion.
type Worker struct {
	tasks    Tasks
	interval time.Duration
	report   func(error)
	mu       sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
	started  bool
}

func New(tasks Tasks, interval time.Duration, report func(error)) (*Worker, error) {
	if tasks == nil || interval < 10*time.Millisecond || interval > time.Minute {
		return nil, errors.New("invalid account closure worker configuration")
	}
	return &Worker{tasks: tasks, interval: interval, report: report}, nil
}
func (w *Worker) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return errors.New("account closure worker already started")
	}
	w.started = true
	ctx, w.cancel = context.WithCancel(ctx)
	w.done = make(chan struct{})
	done := w.done
	w.mu.Unlock()
	defer close(done)
	delay := w.interval
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := w.tasks.Tick(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if w.report != nil {
				w.report(err)
			}
		} else {
			delay = w.interval
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if err != nil {
			delay = min(delay*2, time.Minute)
		}
	}
}
func (w *Worker) Stop(ctx context.Context) error {
	w.mu.Lock()
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
