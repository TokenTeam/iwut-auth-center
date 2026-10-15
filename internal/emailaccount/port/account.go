package port

import (
	"context"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/emailaccount/domain"
	pwd "iwut-auth-center/internal/password/domain"
	reg "iwut-auth-center/internal/registration/port"
	"time"
)

type Operation struct {
	OperationID, RequestID, Purpose, Actor, AuthID, Email, ServiceID, KeyID, Status string
	PublicKey, Fingerprint, Challenge, RequestMAC, CodeMAC                          []byte
	AccountRevision, DirectoryRevision                                              int64
	FailedAttempts                                                                  int
	CreatedAt, ExpiresAt, ResendAfter, RetainUntil                                  time.Time
	ResultDirectoryRevision, ResultRoleRevision                                     int64
}
type Snapshot struct {
	Session   auth.Session
	Directory domain.Directory
	Password  pwd.Record
}
type Registration struct {
	Commit    reg.RegistrationCommit
	Password  pwd.Material
	BindingID string
}
type Mutation struct {
	AuthID, Purpose, RequestID, OperationID, BindingID, KeyID          string
	DirectoryRevision, RoleRevision, PasswordRevision, AccountRevision int64
	RequestMAC                                                         []byte
	CreatedAt, RetainUntil                                             time.Time
}
type Repository interface {
	Snapshot(context.Context, []byte, bool, time.Time) (Snapshot, error)
	Begin(context.Context, Operation, []byte, string, time.Time) (Operation, bool, error)
	Get(context.Context, string) (Operation, error)
	Fail(context.Context, string, time.Time) error
	Complete(context.Context, Operation, []byte, *Registration, string, time.Time) (domain.Directory, error)
	FindMutation(context.Context, []byte, string, string, time.Time) (Mutation, bool, error)
	Mutate(context.Context, Snapshot, Mutation, time.Time) (domain.Directory, error)
}
type Protocol interface {
	KeyID() string
	MutationKeyID(string) string
	ValidID(string) bool
	RequestMAC(Operation) ([]byte, error)
	CodeMAC(Operation, string) ([]byte, error)
	Payload(Operation) ([]byte, error)
	MutationMAC(Mutation, string) ([]byte, error)
	AddressQuotaKey(string) string
	NewCode() (string, error)
}
type Sender interface {
	Send(context.Context, string, string, string, time.Time) error
}
