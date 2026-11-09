package port

import (
	"context"
	"time"

	"iwut-auth-center/internal/scriptmaintainer/domain"
)

type Repository interface {
	Get(context.Context, string, string) (domain.State, error)
	Manage(context.Context, domain.Command) (domain.State, error)
}

type Limiter interface {
	AllowBegin(string, time.Time) bool
	AllowComplete(string, time.Time) bool
}
