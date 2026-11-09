package port

import (
	"context"
	"time"

	"iwut-auth-center/internal/applicationoperations/domain"
)

type Repository interface {
	Manage(context.Context, domain.Command) (domain.State, error)
	Get(context.Context, string, string) (domain.State, error)
	GetOwn(context.Context, string) (domain.OwnState, error)
}

type Limiter interface {
	AllowBegin(string, time.Time) bool
	AllowComplete(string, time.Time) bool
}
