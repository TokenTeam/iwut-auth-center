package port

import (
	"context"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	"time"
)

type Repository interface {
	Authenticate(context.Context, []byte, time.Time) (d.Caller, error)
	List(context.Context, []byte, int, string, time.Time) (d.Page, error)
	SetLabel(context.Context, []byte, string, string, int64, string, time.Time) (d.LabelResult, error)
	Begin(context.Context, []byte, d.Operation, time.Time) (d.Operation, error)
	ReadForComplete(context.Context, []byte, string, time.Time) (d.Operation, error)
	Fail(context.Context, []byte, string, time.Time) error
	Complete(context.Context, []byte, string, []byte, int64, string, time.Time) error
}
type Protocol interface {
	NewID() (string, error)
	RandomBytes(int) ([]byte, error)
	SigningPayload(d.Operation) ([]byte, error)
	Verify([]byte, []byte, []byte) bool
	ValidSignature([]byte) bool
}
type Limiter interface{ AllowAccount(string, time.Time) bool }
