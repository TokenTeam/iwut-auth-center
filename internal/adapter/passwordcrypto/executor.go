package passwordcrypto

import (
	"context"
	"iwut-auth-center/internal/password/domain"
	"time"
)

type Executor struct {
	running, admitted chan struct{}
	wait              time.Duration
}

func NewExecutor(concurrency, queue int, wait time.Duration) (*Executor, error) {
	if concurrency < 1 || concurrency > 32 || queue < 0 || queue > 1024 || wait <= 0 || wait > 10*time.Second {
		return nil, domain.ErrUnavailable
	}
	return &Executor{make(chan struct{}, concurrency), make(chan struct{}, concurrency+queue), wait}, nil
}

func (e *Executor) Do(ctx context.Context, fn func()) error {
	if ctx == nil || fn == nil {
		return domain.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case e.admitted <- struct{}{}:
	default:
		return domain.ErrLimited
	}
	defer func() { <-e.admitted }()
	timer := time.NewTimer(e.wait)
	defer timer.Stop()
	select {
	case e.running <- struct{}{}:
	case <-timer.C:
		return domain.ErrLimited
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-e.running }()
	if err := ctx.Err(); err != nil {
		return err
	}
	// Argon2 is synchronous and not interruptible. Cancellation cannot release
	// this slot before the computation actually finishes.
	fn()
	return ctx.Err()
}
