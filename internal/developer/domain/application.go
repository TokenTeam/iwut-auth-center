package domain

import (
	"errors"
	"time"
)

var (
	ErrApplicationInvalid     = errors.New("INVALID_DEVELOPER_APPLICATION_REQUEST")
	ErrApplicationSession     = errors.New("SESSION_INVALID")
	ErrEmailRequired          = errors.New("DEVELOPER_EMAIL_REQUIRED")
	ErrEmailLoginUnavailable  = errors.New("DEVELOPER_EMAIL_LOGIN_UNAVAILABLE")
	ErrApplicationExists      = errors.New("DEVELOPER_APPLICATION_EXISTS")
	ErrReapplication          = errors.New("DEVELOPER_REAPPLICATION_NOT_ALLOWED")
	ErrApplicationRate        = errors.New("DEVELOPER_APPLICATION_RATE_LIMITED")
	ErrApplicationUnavailable = errors.New("DEVELOPER_APPLICATION_UNAVAILABLE")
)

type ApplicationState struct {
	AuthID        string
	Status        DeveloperStatus
	ActivatedAt   *time.Time
	EmailRevision int64
}
type ApplicationBlocker string

const (
	EmailRequired           ApplicationBlocker = "EMAIL_REQUIRED"
	EmailLoginUnavailable   ApplicationBlocker = "EMAIL_LOGIN_UNAVAILABLE"
	AlreadyDeveloper        ApplicationBlocker = "ALREADY_DEVELOPER"
	ExistingApplication     ApplicationBlocker = "EXISTING_APPLICATION"
	ReapplicationNotAllowed ApplicationBlocker = "REAPPLICATION_NOT_ALLOWED"
)

func (s ApplicationState) Valid() bool {
	return s.AuthID != "" && (s.Status == "" || s.Status.IsValid()) && s.EmailRevision >= 0 && (s.ActivatedAt == nil || s.Status != "" && s.ActivatedAt.UnixMilli() > 0)
}
func (s ApplicationState) Apply(ready bool) (bool, error) {
	if !s.Valid() {
		return false, ErrApplicationUnavailable
	}
	switch s.Status {
	case DeveloperStatusApproved:
		return false, nil
	case DeveloperStatusPending:
		return false, ErrApplicationExists
	case DeveloperStatusRejected, DeveloperStatusSuspended:
		return false, ErrReapplication
	}
	if s.EmailRevision == 0 {
		return false, ErrEmailRequired
	}
	if !ready {
		return false, ErrEmailLoginUnavailable
	}
	return true, nil
}
func (s ApplicationState) Blockers(ready bool) []ApplicationBlocker {
	switch s.Status {
	case DeveloperStatusApproved:
		return []ApplicationBlocker{AlreadyDeveloper}
	case DeveloperStatusPending:
		return []ApplicationBlocker{ExistingApplication}
	case DeveloperStatusRejected, DeveloperStatusSuspended:
		return []ApplicationBlocker{ReapplicationNotAllowed}
	}
	out := []ApplicationBlocker{}
	if s.EmailRevision == 0 {
		out = append(out, EmailRequired)
	}
	if !ready {
		out = append(out, EmailLoginUnavailable)
	}
	return out
}
