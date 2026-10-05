package port

import (
	"context"
	d "iwut-auth-center/internal/developerwithdrawal/domain"
	owner "iwut-auth-center/internal/ownerexit/domain"
	"time"
)

type Repository interface {
	Authenticate(context.Context, []byte, time.Time) (string, error)
	Prepare(context.Context, []byte, string, string, int64, time.Time) (owner.Operation, error)
	Read(context.Context, []byte, string, time.Time) (d.Result, error)
	Confirm(context.Context, []byte, string, time.Time) (d.Result, error)
	Cancel(context.Context, []byte, string, time.Time) (d.Result, error)
}
type Tokens interface {
	TokenDigest(string) ([]byte, error)
	NewID() (string, error)
}

type Limiter interface {
	AllowBegin(string, time.Time) bool
	AllowLocator(string, time.Time) bool
}
