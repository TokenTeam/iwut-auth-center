package port

import (
	"context"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/emailbinding/domain"
	reg "iwut-auth-center/internal/registration/port"
	"time"
)

type Repository interface {
	CheckSession(context.Context, []byte, time.Time) (auth.Session, error)
	Begin(context.Context, Operation, []byte, string, time.Time) (Operation, bool, error)
	Get(context.Context, string) (Operation, error)
	Fail(context.Context, string, time.Time) error
	Complete(context.Context, Operation, []byte, *reg.RegistrationCommit, time.Time) (Activated, error)
	Own(context.Context, []byte, time.Time) (Binding, error)
}
type Protocol interface {
	KeyID() string
	ValidID(string) bool
	RequestMAC(domain.Begin, string) []byte
	CodeMAC(Operation, string) []byte
	Payload(Operation) ([]byte, error)
	NewCode() (string, error)
}
type Sender interface {
	Send(context.Context, string, string, string, time.Time) error
}

type Operation struct {
	Proof                                auth.Operation
	RequestID, Owner, Mode, Email, KeyID string
	RequestMAC, CodeMAC                  []byte
	Revision                             int64
	ResendAfter, RetainUntil, VerifiedAt time.Time
	ResultRevision                       int64
}
type Started struct {
	Operation      Operation
	SigningPayload []byte
}
type Activated struct {
	OperationID, Mode, Email string
	VerifiedAt               time.Time
	Revision                 int64
	Registration             *auth.Established
}
type Binding struct {
	AuthID, Email, PendingID string
	Revision                 int64
	VerifiedAt               time.Time
	Pending                  *Operation
}
