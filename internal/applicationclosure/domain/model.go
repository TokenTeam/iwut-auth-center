package domain

import (
	"errors"
	"time"
)

var (
	ErrInvalid      = errors.New("INVALID_APPLICATION_CLOSURE_REQUEST")
	ErrNotFound     = errors.New("APPLICATION_CLOSURE_NOT_FOUND")
	ErrConflict     = errors.New("APPLICATION_CLOSURE_CONFLICT")
	ErrUnavailable  = errors.New("APPLICATION_CLOSURE_UNAVAILABLE")
	ErrInconsistent = errors.New("APPLICATION_CLOSURE_STATE_INCONSISTENT")
)

type Tombstone struct {
	ApplicationID, ClosureID, ReceiptID, CallerServiceID string
	ClosingStartedAt, AppliedAt                          time.Time
}
