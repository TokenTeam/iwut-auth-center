package port

import (
	"context"
	auth "iwut-auth-center/internal/authentication/domain"
	d "iwut-auth-center/internal/campuscertification/domain"
	"time"
)

type Operation struct {
	Proof                    auth.Operation
	RequestID, Email, KeyID  string
	RequestMAC, CodeMAC      []byte
	ResendAfter, RetainUntil time.Time
}

type Repository interface {
	CheckSession(context.Context, []byte, time.Time) (auth.Session, error)
	Begin(context.Context, Operation, []byte, string, time.Time) (Operation, bool, error)
	Get(context.Context, string) (Operation, error)
	Complete(context.Context, Operation, []byte, time.Time) (d.Certification, error)
	Own(context.Context, []byte, time.Time) (d.Certification, error)
}
type Protocol interface {
	KeyID() string
	ValidID(string) bool
	RequestMAC(d.Begin, string, int64) []byte
	CodeMAC(Operation, string) []byte
	NewCode() (string, error)
}
type Sender interface {
	Send(context.Context, string, string, string, time.Time) error
}
