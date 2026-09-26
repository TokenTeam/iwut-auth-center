package domain

import (
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidHandle          = errors.New("INVALID_DEVELOPER_HANDLE")
	ErrHandleTaken            = errors.New("DEVELOPER_HANDLE_TAKEN")
	ErrHandleChange           = errors.New("DEVELOPER_HANDLE_CHANGE_NOT_ALLOWED")
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
	DeveloperHandle string
	AuthID          string
	Status          DeveloperStatus
	ActivatedAt     *time.Time
	EmailRevision   int64
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
	handle, err := NormalizeDeveloperHandle(s.DeveloperHandle)
	if s.DeveloperHandle != "" && (err != nil || handle != s.DeveloperHandle || s.Status == "") {
		return false
	}
	return s.AuthID != "" && (s.Status == "" || s.Status.IsValid()) && s.EmailRevision >= 0 && (s.ActivatedAt == nil || s.Status != "" && s.ActivatedAt.UnixMilli() > 0)
}
func (s ApplicationState) Apply(ready bool, candidate string) (bool, error) {
	handle, err := NormalizeDeveloperHandle(candidate)
	if err != nil {
		return false, err
	}
	if !s.Valid() {
		return false, ErrApplicationUnavailable
	}
	switch s.Status {
	case DeveloperStatusApproved:
		if s.DeveloperHandle != "" {
			if handle != s.DeveloperHandle {
				return false, ErrHandleChange
			}
			return false, nil
		}
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
		if s.DeveloperHandle != "" {
			return []ApplicationBlocker{AlreadyDeveloper}
		}
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

// HandleClaim is empty for read-only/idempotent confirmation. A non-empty handle
// is claimed atomically, activating only a previously ordinary USER.
type HandleClaim struct{ DeveloperHandle string }

func NormalizeDeveloperHandle(raw string) (string, error) {
	if len(raw) < 3 || len(raw) > 32 {
		return "", ErrInvalidHandle
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !letter && (i == 0 || !(c >= '0' && c <= '9' || c == '_' || c == '-')) {
			return "", ErrInvalidHandle
		}
	}
	return strings.ToLower(raw), nil
}
