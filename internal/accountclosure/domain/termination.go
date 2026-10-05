package domain

import "time"

// Termination is the minimum durable fact that must survive database restoration.
type Termination struct {
	AuthID          string
	AccountRevision int64
	TerminatedAt    time.Time
	OperationID     string
}
