package port

import (
	"context"
	"errors"

	"iwut-auth-center/internal/accountclosure/domain"
)

var ErrReservationsNotFound = errors.New("termination namespace reservations not found")

// TerminationLedger is independent of the business database backup lifecycle.
// Store acknowledges only a durable record; Records rejects corrupt entries.
type TerminationLedger interface {
	StoreReservations(context.Context, domain.NamespaceReservations) error
	Reservations(context.Context, string) (domain.NamespaceReservations, error)
	Store(context.Context, domain.Termination) error
	Records(context.Context) ([]domain.Termination, error)
}
