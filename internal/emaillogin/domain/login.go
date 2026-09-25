package domain

import (
	"errors"
	"time"
)

const (
	ProtocolVersion      = "iwut-email-login-v1"
	Purpose              = "LOGIN_WITH_EMAIL"
	AuthenticationMethod = "EMAIL_CODE_AND_DEVICE"
)

var (
	ErrInvalid     = errors.New("INVALID_EMAIL_LOGIN_REQUEST")
	ErrFailed      = errors.New("EMAIL_LOGIN_FAILED")
	ErrCredential  = errors.New("EMAIL_LOGIN_CREDENTIAL_UNAVAILABLE")
	ErrConflict    = errors.New("EMAIL_LOGIN_REQUEST_CONFLICT")
	ErrCompleted   = errors.New("LOGIN_ALREADY_COMPLETED")
	ErrRate        = errors.New("EMAIL_LOGIN_RATE_LIMITED")
	ErrDelivery    = errors.New("EMAIL_DELIVERY_UNAVAILABLE")
	ErrUnavailable = errors.New("EMAIL_LOGIN_UNAVAILABLE")
)
var Errors = []error{ErrInvalid, ErrFailed, ErrCredential, ErrConflict, ErrCompleted, ErrRate, ErrDelivery, ErrUnavailable}

type Begin struct {
	RequestID, Email, ProtocolVersion, Source string
	PublicKey                                 []byte
}

// Operation is the immutable login proof and eligibility snapshot. Secrets,
// signing payloads and association data must never be persisted here.
type Operation struct {
	OperationID, RequestID, Purpose, ProtocolVersion, ServiceID, ApplicationID string
	Email, KeyID, AuthID, CredentialID, Status                                 string
	PublicKey, Fingerprint, Challenge, RequestMAC, CodeMAC                     []byte
	Eligible, CredentialAcceptable                                             bool
	EmailBindingRevision                                                       int64
	FailedAttempts                                                             int
	CreatedAt, ExpiresAt, ResendAfter, RetainUntil                             time.Time
	CompletedCredentialID, CompletedSessionID                                  string
}
type Challenge struct {
	OperationID, ProtocolVersion string
	Challenge, SigningPayload    []byte
	ExpiresAt, ResendAfter       time.Time
}
