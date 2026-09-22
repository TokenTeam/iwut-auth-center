package port

import (
	"context"
	"iwut-auth-center/internal/profile/domain"
)

type Repository interface {
	Read(context.Context, string) (domain.Principal, error)
	// Confirm is the final authoritative no-op read; Commit changes only profile.
	Confirm(context.Context, string, int64) (domain.Snapshot, error)
	Commit(context.Context, string, int64, domain.Snapshot) error
}
type Catalog interface {
	Snapshot(context.Context) ([]domain.Definition, error)
}
