package port

import (
	"context"
	"iwut-auth-center/internal/reviewer/domain"
)

type Repository interface {
	Manage(context.Context, domain.Command) (domain.State, error)
	Get(context.Context, string, string) (domain.State, error)
	Bootstrap(context.Context, string) (bool, error)
}
