package domain

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrIdentity    = errors.New("ACCOUNT_MANAGEMENT_IDENTITY_INVALID")
	ErrForbidden   = errors.New("ACCOUNT_MANAGEMENT_FORBIDDEN")
	ErrInvalid     = errors.New("INVALID_ACCOUNT_STATUS_REQUEST")
	ErrSubject     = errors.New("ACCOUNT_SUBJECT_UNAVAILABLE")
	ErrConflict    = errors.New("ACCOUNT_STATUS_CONFLICT")
	ErrLastAdmin   = errors.New("LAST_PLATFORM_ADMIN_REQUIRED")
	ErrExhausted   = errors.New("ACCOUNT_REVISION_EXHAUSTED")
	ErrRate        = errors.New("ACCOUNT_MANAGEMENT_RATE_LIMITED")
	ErrUnavailable = errors.New("ACCOUNT_MANAGEMENT_UNAVAILABLE")
)

type State struct {
	AuthID, Status string
	Revision       int64
	ChangedAt      *time.Time
}
type Command struct {
	ActorAuthID, SubjectAuthID, Action, Reason string
	ExpectedRevision                           int64
}

func ValidSubject(id string) bool {
	return id != "" && len(id) <= 128 && strings.TrimSpace(id) == id && utf8.ValidString(id)
}
func (c Command) Validate() error {
	if !ValidSubject(c.ActorAuthID) || !ValidSubject(c.SubjectAuthID) || c.ExpectedRevision <= 0 || (c.Action != "DISABLE" && c.Action != "RESTORE") || len(c.Reason) < 1 || len(c.Reason) > 1024 || !utf8.ValidString(c.Reason) || strings.TrimSpace(c.Reason) != c.Reason {
		return ErrInvalid
	}
	return nil
}
