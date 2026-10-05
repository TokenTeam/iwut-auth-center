package domain

import (
	"errors"
	"time"
)

var (
	ErrInvalid     = errors.New("INVALID_DEVELOPER_WITHDRAWAL_REQUEST")
	ErrSession     = errors.New("SESSION_INVALID")
	ErrNotFound    = errors.New("DEVELOPER_WITHDRAWAL_NOT_FOUND")
	ErrConflict    = errors.New("DEVELOPER_WITHDRAWAL_CONFLICT")
	ErrWithdrawn   = errors.New("ALREADY_WITHDRAWN")
	ErrRate        = errors.New("DEVELOPER_WITHDRAWAL_RATE_LIMITED")
	ErrUnavailable = errors.New("DEVELOPER_WITHDRAWAL_UNAVAILABLE")
)

type Result struct {
	OperationID, State, DeveloperStatus, Blocker string
	DeveloperRevision                            int64
	ExpiresAt                                    time.Time
	CompletedAt                                  *time.Time
}
