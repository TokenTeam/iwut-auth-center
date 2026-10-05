// Package usecase coordinates durable Auth decisions with App ownership barriers.
package usecase

import (
	"context"
	d "iwut-auth-center/internal/ownerexit/domain"
	p "iwut-auth-center/internal/ownerexit/port"
	"time"
)

type Coordinator struct {
	repository p.Repository
	app        p.App
}

func New(r p.Repository, a p.App) *Coordinator { return &Coordinator{r, a} }

// Prepare never guesses a cancellation on an unknown remote outcome. A durable
// PENDING operation survives every RPC/transaction failure and is retried.
func (c *Coordinator) Prepare(ctx context.Context, op d.Operation) (d.Operation, error) {
	current, e := c.repository.Get(ctx, op.AuthID, op.OperationID)
	if e != nil {
		return d.Operation{}, e
	}
	if current.Decision != d.Pending || current.ReceiptID != "" {
		return current, nil
	}
	prepared, e := c.app.Prepare(ctx, current)
	if e != nil {
		return current, d.ErrUnavailable
	}
	return c.repository.BindPreparation(ctx, current.AuthID, current.OperationID, prepared, time.Now().UTC())
}
func (c *Coordinator) Tick(ctx context.Context) error {
	pending, e := c.repository.Due(ctx, time.Now().UTC(), 100)
	if e != nil {
		return e
	}
	var failed bool
	for _, op := range pending {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if op.Decision == d.Pending {
			if op.ReceiptID == "" {
				_, e = c.Prepare(ctx, op)
			} else {
				e = nil
			}
		} else {
			var status d.Status
			if op.NotificationPending {
				status, e = c.app.Finish(ctx, op)
			} else {
				status, e = c.app.Status(ctx, op)
			}
			if e == nil {
				e = c.repository.Acknowledge(ctx, op, status, time.Now().UTC())
			}
		}
		// Advance pending checks and failed deliveries. Terminal acknowledged work is
		// removed by Acknowledge; no successful Finish is mistaken for cleanup done.
		if op.Decision == d.Pending || e != nil {
			if re := c.repository.Retry(ctx, op, time.Now().UTC()); re != nil {
				e = re
			}
		}
		if e != nil {
			failed = true
		}
	}
	if failed {
		return d.ErrUnavailable
	}
	return nil
}
