package port

import (
	"context"
	"iwut-auth-center/internal/account/domain"
)

type Repository interface {
	Get(context.Context, string, string) (domain.State, error)
	Manage(context.Context, domain.Command) (domain.State, error)
}
