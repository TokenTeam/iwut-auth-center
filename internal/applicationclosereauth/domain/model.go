package domain

import (
	"errors"
	"time"
)

const (
	Pending   = "PENDING"
	Completed = "COMPLETED"
)

var (
	ErrInvalid      = errors.New("INVALID_APPLICATION_CLOSE_REAUTH_REQUEST")
	ErrFailed       = errors.New("APPLICATION_CLOSE_REAUTH_FAILED")
	ErrRate         = errors.New("APPLICATION_CLOSE_REAUTH_RATE_LIMITED")
	ErrUnavailable  = errors.New("APPLICATION_CLOSE_REAUTH_UNAVAILABLE")
	ErrInconsistent = errors.New("APPLICATION_CLOSE_REAUTH_STATE_INCONSISTENT")
)

type Operation struct {
	OperationID, AuthID, SessionID, CredentialID, ApplicationID string
	Challenge, PublicKey, SignatureDigest                       []byte
	AccountRevision, PasswordRevision, FailedAttempts           int64
	State                                                       string
	CreatedAt, ExpiresAt                                        time.Time
	JTI                                                         string
	AuthTime, IssuedAt, NotBefore, ProofExpiresAt               time.Time
}

type Challenge struct {
	OperationID string
	Challenge   []byte
	ExpiresAt   time.Time
}

type Proof struct {
	JWS       string
	ExpiresAt time.Time
}

type Claims struct {
	Issuer, Subject, Audience, TokenType, Purpose, ApplicationID, JTI string
	AuthTime, IssuedAt, NotBefore, ExpiresAt                          time.Time
}
