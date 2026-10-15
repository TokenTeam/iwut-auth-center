// Package domain contains the permanent campus membership fact, not student
// status, profile values or an application entitlement balance.
package domain

import (
	"errors"
	"strings"
	"time"
)

const Institution = "WHUT"
const Purpose = "CERTIFY_CAMPUS_WHUT"

var (
	ErrInvalid      = errors.New("INVALID_CAMPUS_CERTIFICATION_REQUEST")
	ErrSession      = errors.New("SESSION_INVALID")
	ErrVerification = errors.New("CAMPUS_VERIFICATION_FAILED")
	ErrConflict     = errors.New("CAMPUS_REQUEST_CONFLICT")
	ErrCertified    = errors.New("CAMPUS_ALREADY_CERTIFIED")
	ErrRate         = errors.New("CAMPUS_RATE_LIMITED")
	ErrDelivery     = errors.New("EMAIL_DELIVERY_UNAVAILABLE")
	ErrUnavailable  = errors.New("CAMPUS_CERTIFICATION_UNAVAILABLE")
	ErrNotFound     = errors.New("CAMPUS_CERTIFICATION_NOT_FOUND")
)
var Errors = []error{ErrInvalid, ErrSession, ErrVerification, ErrConflict, ErrCertified, ErrRate, ErrDelivery, ErrUnavailable, ErrNotFound}

type Begin struct{ RequestID, Email, Source string }
type Certification struct {
	Institution string
	CertifiedAt time.Time
}

// IsWHUTEmail accepts only an already normalized, valid address with the exact
// domain. Validation and normalization belong to the shared email boundary.
func IsWHUTEmail(email string) bool {
	return strings.Count(email, "@") == 1 && strings.HasSuffix(email, "@whut.edu.cn") && len(email) > len("@whut.edu.cn")
}

func (c Certification) Valid() bool {
	return c.Institution == Institution && c.CertifiedAt.UnixMilli() > 0 && c.CertifiedAt.Equal(c.CertifiedAt.Truncate(time.Millisecond))
}
