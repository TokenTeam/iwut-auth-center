package ownerexitworker

import (
	"context"
	"iwut-auth-center/internal/ownerexit/usecase"
	"sync"
	"time"
)

type Worker struct {
	coordinator *usecase.Coordinator
	mu          sync.Mutex
	cancel      context.CancelFunc
}

func New(c *usecase.Coordinator) *Worker { return &Worker{coordinator: c} }
func (w *Worker) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	w.cancel = cancel
	w.mu.Unlock()
	defer cancel()
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			_ = w.coordinator.Tick(ctx)
		}
	}
}
func (w *Worker) Stop(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		w.cancel()
	}
	return nil
}
