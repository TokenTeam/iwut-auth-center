package port

import (
	"context"
	"errors"

	"iwut-auth-center/internal/developer/domain"
)

var ErrDeveloperStatusUnavailable = errors.New("developer status unavailable")

type PrincipalRepository interface {
	BatchGet(ctx context.Context, authIDs []domain.AuthID) ([]domain.Principal, error)
}
