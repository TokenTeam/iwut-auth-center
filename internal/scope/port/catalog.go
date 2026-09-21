package port

import (
	"context"
	"errors"

	"iwut-auth-center/internal/scope/domain"
)

var ErrScopeCatalogUnavailable = errors.New("scope catalog unavailable")

type Catalog interface {
	GetSnapshot(ctx context.Context) (domain.Snapshot, error)
}
