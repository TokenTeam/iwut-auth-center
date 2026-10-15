package port

import (
	"context"
	d "iwut-auth-center/internal/accountclosure/domain"
	owner "iwut-auth-center/internal/ownerexit/domain"
	"time"
)

type Protocol interface {
	SigningPayload(d.Proof) ([]byte, error)
	Verify([]byte, []byte, []byte) bool
	NewID() (string, error)
	RandomBytes(int) ([]byte, error)
	NewToken(d.TokenPurpose) (string, []byte, error)
	TokenDigest(d.TokenPurpose, string) ([]byte, error)
}
type Repository interface {
	Begin(context.Context, d.Operation) (d.Operation, error)
	Read(context.Context, string) (d.Operation, error)
	FailProof(context.Context, string, time.Time) error
	Prepare(context.Context, string, int64, time.Time) (d.Operation, owner.Operation, error)
	Ready(context.Context, string, []byte, []byte, time.Time) (d.Operation, error)
	Confirm(context.Context, string, []byte, time.Time) (d.Operation, error)
	Cancel(context.Context, string, []byte, time.Time) (d.Operation, error)
	Receipt(context.Context, string, []byte, time.Time) (d.Operation, error)
	Pending(context.Context, time.Time, int) ([]d.Operation, error)
	MarkLedger(context.Context, d.Termination) error
	VerifyLedger(context.Context, []d.Termination) error
	CaptureReservations(context.Context, d.Termination) (d.NamespaceReservations, error)
	ReplayReservations(context.Context, d.NamespaceReservations) error
	Attempt(context.Context, string, time.Time) error
	Replay(context.Context, d.Termination) error
	RecoverOwner(context.Context, d.Termination, owner.Status) error
	Cleanup(context.Context, string, time.Time, int) (bool, error)
	Retain(context.Context, time.Time, int) error
}
