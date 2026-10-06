package port

import (
	"context"
	"time"

	d "iwut-auth-center/internal/applicationclosure/domain"
)

type Repository interface {
	Apply(context.Context, string, string, time.Time, string, string, time.Time) (d.Tombstone, error)
	Get(context.Context, string, string) (d.Tombstone, error)
}
