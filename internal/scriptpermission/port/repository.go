package port

import (
	"context"
	"time"

	"iwut-auth-center/internal/scriptpermission/domain"
)

type Repository interface {
	GetOwn(context.Context, string) (domain.State, error)
	Get(context.Context, string, string) (domain.State, error)
	Manage(context.Context, domain.Command) (domain.State, error)
}

type Limiter interface {
	AllowBegin(string, time.Time) bool
	AllowComplete(string, time.Time) bool
}
