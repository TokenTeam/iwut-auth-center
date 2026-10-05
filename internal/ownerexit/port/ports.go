package port

import (
	"context"
	d "iwut-auth-center/internal/ownerexit/domain"
	"time"
)

type App interface {
	Prepare(context.Context, d.Operation) (d.Preparation, error)
	Finish(context.Context, d.Operation) (d.Status, error)
	Status(context.Context, d.Operation) (d.Status, error)
}
type Repository interface {
	Get(context.Context, string, string) (d.Operation, error)
	BindPreparation(context.Context, string, string, d.Preparation, time.Time) (d.Operation, error)
	Due(context.Context, time.Time, int) ([]d.Operation, error)
	Acknowledge(context.Context, d.Operation, d.Status, time.Time) error
	Retry(context.Context, d.Operation, time.Time) error
}
