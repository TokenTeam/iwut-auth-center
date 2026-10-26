package port

import (
	"context"
	d "iwut-auth-center/internal/scopemanagement/domain"
	"time"
)

type Repository interface {
	Get(context.Context, string) (d.Snapshot, error)
	Change(context.Context, d.Command) (d.Operation, error)
	Operation(context.Context, string, string) (d.Operation, error)
}

type Limiter interface {
	AllowBegin(string, time.Time) bool
	AllowComplete(string, time.Time) bool
}
