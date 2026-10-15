package port

import (
	"context"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/password/domain"
	"time"
)

const LoginProtocolVersion = "iwut-password-login-v1"

type Login struct {
	OperationID, RequestID, Email, AddressKey, AuthID, ServiceID, KeyID, Status string
	Acceptable                                                                  bool
	AccountRevision, PasswordRevision, RoleRevision, FailedAttempts             int64
	PublicKey, Fingerprint, Challenge, RequestMAC                               []byte
	CreatedAt, ExpiresAt, RetainUntil                                           time.Time
}
type LoginSnapshot struct {
	Operation Login
	Password  domain.Record
	Usable    bool
}
type LoginCommit struct {
	Snapshot   LoginSnapshot
	Credential auth.Credential
	Session    auth.Session
	Upgrade    domain.Material
}
type LoginRepository interface {
	BeginLogin(context.Context, Login, time.Time) (Login, error)
	ReadLogin(context.Context, string, time.Time) (LoginSnapshot, error)
	FailLogin(context.Context, string, time.Time) error
	CompleteLogin(context.Context, LoginCommit, time.Time) (string, error)
}
type LoginProtocol interface {
	KeyID() string
	ServiceID() string
	LoginRequestMAC(string, string, []byte) ([]byte, error)
	LoginPayload(string, string, []byte, []byte, time.Time) ([]byte, error)
}

// RehashEngine upgrades only already-verified secrets without new-password policy.
type RehashEngine interface {
	Engine
	Rehash(context.Context, string) (domain.Material, error)
}
