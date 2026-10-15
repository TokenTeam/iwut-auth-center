package domain

import (
	"errors"

	"strings"
)

const (
	Register            = "REGISTER"
	Bind                = "BIND"
	RegistrationPurpose = "REGISTER_WITH_EMAIL"
	BindingPurpose      = "BIND_EMAIL"
	ProtocolVersion     = "iwut-email-registration-v2"
)

var (
	ErrInvalid      = errors.New("INVALID_EMAIL_REQUEST")
	ErrFlow         = errors.New("EMAIL_FLOW_MISMATCH")
	ErrVerification = errors.New("EMAIL_VERIFICATION_FAILED")
	ErrRevision     = errors.New("EMAIL_REVISION_CONFLICT")
	ErrConflict     = errors.New("EMAIL_REQUEST_CONFLICT")
	ErrActive       = errors.New("EMAIL_ALREADY_ACTIVE")
	ErrOccupied     = errors.New("EMAIL_UNAVAILABLE")
	ErrCompleted    = errors.New("REGISTRATION_ALREADY_COMPLETED")
	ErrCredential   = errors.New("CREDENTIAL_ALREADY_REGISTERED")
	ErrRate         = errors.New("EMAIL_RATE_LIMITED")
	ErrDelivery     = errors.New("EMAIL_DELIVERY_UNAVAILABLE")
	ErrUnavailable  = errors.New("EMAIL_BINDING_UNAVAILABLE")
	ErrSession      = errors.New("SESSION_INVALID")
)
var Errors = []error{ErrInvalid, ErrFlow, ErrVerification, ErrRevision, ErrConflict, ErrActive, ErrOccupied, ErrCompleted, ErrCredential, ErrRate, ErrDelivery, ErrUnavailable, ErrSession}

type Begin struct {
	RequestID, Email, Mode, ProtocolVersion, Source string
	PublicKey                                       []byte
	Revision                                        *int64
}

func NormalizeEmail(raw string) (string, error) {
	s := strings.Trim(raw, " ")
	if len(s) > 254 || strings.Count(s, "@") != 1 {
		return "", ErrInvalid
	}
	p := strings.Split(s, "@")
	local, host := p[0], p[1]
	if len(local) == 0 || len(local) > 64 {
		return "", ErrInvalid
	}
	atom := "!#$%&'*+-/=?^_`{|}~"
	for _, a := range strings.Split(local, ".") {
		if a == "" {
			return "", ErrInvalid
		}
		for _, c := range a {
			if !asciiAlnum(c) && !strings.ContainsRune(atom, c) {
				return "", ErrInvalid
			}
		}
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", ErrInvalid
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", ErrInvalid
		}
		for _, c := range l {
			if !asciiAlnum(c) && c != '-' {
				return "", ErrInvalid
			}
		}
	}
	return strings.ToLower(s), nil
}
func asciiAlnum(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
func ValidCode(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
