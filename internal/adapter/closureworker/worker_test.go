package closureworker

import (
	"context"
	"errors"
	"testing"
	"time"
)

type taskFunc func(context.Context) error

func (f taskFunc) Tick(ctx context.Context) error { return f(ctx) }

func TestWorkerShutdownCancelsInflightTask(t *testing.T) {
	entered := make(chan struct{})
	finished := make(chan struct{})
	w, err := New(taskFunc(func(ctx context.Context) error { close(entered); <-ctx.Done(); close(finished); return ctx.Err() }), time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- w.Start(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("Stop returned before task completed")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := w.Start(ctx); err == nil {
		t.Fatal("duplicate worker start accepted")
	}
}

func TestWorkerRetriesAfterFailureWithoutPublicRequests(t *testing.T) {
	retried := make(chan struct{})
	reported := make(chan error, 1)
	attempt := 0
	w, err := New(taskFunc(func(ctx context.Context) error {
		attempt++
		if attempt == 1 {
			return errors.New("dependency unavailable")
		}
		close(retried)
		<-ctx.Done()
		return ctx.Err()
	}), 10*time.Millisecond, func(err error) { reported <- err })
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- w.Start(context.Background()) }()
	select {
	case <-retried:
	case <-time.After(time.Second):
		t.Fatal("persisted work was not retried")
	}
	select {
	case <-reported:
	default:
		t.Fatal("background failure was not reported")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
