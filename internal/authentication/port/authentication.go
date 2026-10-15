package port

import (
	"context"
	"errors"
	"iwut-auth-center/internal/authentication/domain"
	"time"
)

var (
	ErrCredentialRegistered     = errors.New("credential already registered")
	ErrInvalidInput             = errors.New("invalid login input")
	ErrAuthenticationFailed     = errors.New("authentication failed")
	ErrAlreadyCompleted         = errors.New("login already completed")
	ErrSessionInvalid           = errors.New("session invalid")
	ErrLimitExceeded            = errors.New("authentication limit exceeded")
	ErrUnavailable              = errors.New("authentication unavailable")
	ErrNotFound                 = errors.New("authentication record not found")
	ErrCredentialReauthRequired = errors.New("credential reauthentication required")
)

type DeviceProtocol interface {
	ValidatePublicKey([]byte) error
	Fingerprint([]byte) ([]byte, error)
	SigningPayload(domain.Operation, []byte) ([]byte, error)
	Verify([]byte, []byte, []byte) bool
	NewID() (string, error)
	RandomBytes(int) ([]byte, error)
	NewSessionToken() (string, []byte, error)
	TokenDigest(string) ([]byte, error)
}

type LoginRepository interface {
	CreateOperation(context.Context, domain.Operation, time.Time) error
	GetOperation(context.Context, string) (domain.Operation, error)
	ResolveCredential(context.Context, domain.Locator) (domain.Credential, bool, error)
	RecordFailure(context.Context, string, time.Time) error
	CompleteLogin(context.Context, domain.Operation, domain.Session, time.Time) error
	CheckSession(context.Context, []byte, time.Time) (domain.Session, error)
}

type Limiter interface {
	AllowBegin(source string, now time.Time) bool
	AllowComplete(locator string, now time.Time) bool
	AllowLocator(locator string, now time.Time) bool
}

type SessionChecker interface {
	Check(context.Context, string) (domain.Session, error)
}
