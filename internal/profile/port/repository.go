package port

import (
	"context"
	"iwut-auth-center/internal/profile/domain"
	"time"
)

type Repository interface {
	Transaction(context.Context, func(context.Context) error) error
	Read(context.Context, string) (domain.Principal, error)
	// Confirm is the final authoritative no-op read; Commit changes only profile.
	Confirm(context.Context, string, int64) (domain.Snapshot, error)
	Commit(context.Context, string, int64, domain.Snapshot) error
}
type Catalog interface {
	Snapshot(context.Context) ([]domain.Definition, error)
}
type AcademicYearProvider interface {
	CurrentAcademicYear(context.Context, time.Time) (int32, error)
}
