package port

import (
	"context"

	"iwut-auth-center/internal/accountclosure/domain"
)

// TerminationLedger is independent of the business database backup lifecycle.
// Store acknowledges only a durable record; Records rejects corrupt entries.
type TerminationLedger interface {
	Store(context.Context, domain.Termination) error
	Records(context.Context) ([]domain.Termination, error)
}
