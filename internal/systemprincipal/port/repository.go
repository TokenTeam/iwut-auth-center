package port

import (
	"context"
	"errors"

	"iwut-auth-center/internal/systemprincipal/domain"
)

var (
	ErrSystemPrincipalNotFound    = errors.New("system principal not found")
	ErrSystemPrincipalUnavailable = errors.New("system principal unavailable")
)

type Repository interface {
	Resolve(ctx context.Context, purpose domain.Purpose) (domain.Principal, error)
}
