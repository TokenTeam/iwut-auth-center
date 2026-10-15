package port

import (
	"context"
	"time"

	d "iwut-auth-center/internal/applicationclosereauth/domain"
)

type Repository interface {
	Begin(context.Context, []byte, string, string, []byte, time.Time, time.Time) (d.Operation, error)
	ReadForComplete(context.Context, []byte, string, string, time.Time) (d.Operation, error)
	Complete(context.Context, []byte, string, string, []byte, int64, d.Claims, time.Time) (d.Operation, error)
	Fail(context.Context, string, time.Time) error
}

type Protocol interface {
	RandomBytes(int) ([]byte, error)
	NewID() (string, error)
	Verify([]byte, []byte, []byte) bool
}

type Signer interface {
	Sign(context.Context, d.Claims) (string, error)
}
