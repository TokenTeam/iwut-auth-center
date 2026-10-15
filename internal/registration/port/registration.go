package port

import (
	"errors"
	auth "iwut-auth-center/internal/authentication/domain"
)

var (
	ErrInvalidInput         = errors.New("invalid registration input")
	ErrUnsupported          = errors.New("registration scheme unsupported")
	ErrProofInvalid         = errors.New("registration proof invalid")
	ErrAlreadyCompleted     = errors.New("registration already completed")
	ErrCredentialRegistered = errors.New("credential already registered")
	ErrRateLimited          = errors.New("registration rate limited")
	ErrInputTooLarge        = errors.New("registration input too large")
	ErrUnavailable          = errors.New("registration unavailable")
)

type RegistrationCommit struct {
	Operation  auth.Operation
	Credential auth.Credential
	Session    auth.Session
}
