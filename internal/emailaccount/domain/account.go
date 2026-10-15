package domain

import (
	"errors"
	"time"
)

const (
	ProtocolVersion = "iwut-email-registration-v3"
	Register        = "REGISTER_WITH_PASSWORD_EMAIL"
	Add             = "ADD_VERIFIED_EMAIL"
	Switch          = "SWITCH_LOGIN_EMAIL"
	Remove          = "REMOVE_VERIFIED_EMAIL"
)

var (
	ErrInvalid           = errors.New("INVALID_EMAIL_REQUEST")
	ErrVerification      = errors.New("EMAIL_VERIFICATION_FAILED")
	ErrDirectoryConflict = errors.New("EMAIL_DIRECTORY_CONFLICT")
	ErrRoleConflict      = errors.New("EMAIL_LOGIN_ROLE_CONFLICT")
	ErrBindingLimit      = errors.New("EMAIL_BINDING_LIMIT_REACHED")
	ErrLoginRemoval      = errors.New("LOGIN_EMAIL_REMOVAL_FORBIDDEN")
	ErrBindingNotFound   = errors.New("EMAIL_BINDING_NOT_FOUND")
	ErrConflict          = errors.New("EMAIL_REQUEST_CONFLICT")
	ErrOccupied          = errors.New("EMAIL_UNAVAILABLE")
	ErrCompleted         = errors.New("REGISTRATION_ALREADY_COMPLETED")
	ErrCredential        = errors.New("CREDENTIAL_ALREADY_REGISTERED")
	ErrLimited           = errors.New("EMAIL_RATE_LIMITED")
	ErrDelivery          = errors.New("EMAIL_DELIVERY_UNAVAILABLE")
	ErrUnavailable       = errors.New("EMAIL_BINDING_UNAVAILABLE")
	ErrSession           = errors.New("SESSION_INVALID")
)
var Errors = []error{ErrInvalid, ErrVerification, ErrDirectoryConflict, ErrRoleConflict, ErrBindingLimit, ErrLoginRemoval, ErrBindingNotFound, ErrConflict, ErrOccupied, ErrCompleted, ErrCredential, ErrLimited, ErrDelivery, ErrUnavailable, ErrSession}

type Binding struct {
	BindingID, AuthID, Email string
	VerifiedAt               time.Time
}
type Directory struct {
	AuthID, LoginBindingID      string
	Revision, LoginRoleRevision int64
	Bindings                    []Binding
	Pending                     []Pending
}
type Pending struct {
	OperationID, Email     string
	ExpiresAt, ResendAfter time.Time
}

func (d Directory) Primary() (Binding, bool) {
	for _, b := range d.Bindings {
		if b.BindingID == d.LoginBindingID {
			return b, true
		}
	}
	return Binding{}, false
}

type Begin struct {
	RequestID, Email, DeviceVersion, Source string
	PublicKey                               []byte
	ExpectedDirectoryRevision               int64
}
type Mutation struct {
	RequestID, BindingID, Password, Source               string
	ExpectedDirectoryRevision, ExpectedLoginRoleRevision int64
}
