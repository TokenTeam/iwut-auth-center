package domain

import (
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

const DeveloperManager = "auth.developer.manage"

var (
	ErrManagementIdentity         = errors.New("INVALID_USER_IDENTITY")
	ErrManagementInvalid          = errors.New("INVALID_DEVELOPER_MANAGEMENT_REQUEST")
	ErrManagementForbidden        = errors.New("DEVELOPER_MANAGEMENT_FORBIDDEN")
	ErrManagementSubject          = errors.New("DEVELOPER_SUBJECT_UNAVAILABLE")
	ErrManagementConflict         = errors.New("DEVELOPER_STATUS_CONFLICT")
	ErrRestoreBlocked             = errors.New("DEVELOPER_RESTORE_BLOCKED")
	ErrDeveloperRevisionExhausted = errors.New("DEVELOPER_REVISION_EXHAUSTED")
	ErrManagementUnavailable      = errors.New("DEVELOPER_MANAGEMENT_UNAVAILABLE")
	ErrManagementRate             = errors.New("DEVELOPER_MANAGEMENT_RATE_LIMITED")
)
var ManagementErrors = []error{ErrManagementIdentity, ErrManagementInvalid, ErrManagementForbidden, ErrManagementSubject, ErrManagementConflict, ErrRestoreBlocked, ErrDeveloperRevisionExhausted, ErrManagementUnavailable, ErrManagementRate}

type ManagedDeveloperState struct {
	AuthID, AccountStatus, Status string
	Revision                      int64
	StatusChangedAt               *time.Time
}

func (s ManagedDeveloperState) Valid() bool {
	if _, e := NewAuthID(s.AuthID); e != nil || strings.TrimSpace(s.AuthID) != s.AuthID || s.Revision < 1 || (s.AccountStatus != "ACTIVE" && s.AccountStatus != "DISABLED") {
		return false
	}
	switch s.Status {
	case "PENDING", "APPROVED", "REJECTED", "SUSPENDED", "WITHDRAWN":
	default:
		return false
	}
	return s.StatusChangedAt == nil || !s.StatusChangedAt.IsZero()
}

type ManageDeveloperCommand struct {
	ActorAuthID, SubjectAuthID, Action, Reason string
	ExpectedRevision                           int64
}

func (c ManageDeveloperCommand) Valid() bool {
	_, a := NewAuthID(c.ActorAuthID)
	_, s := NewAuthID(c.SubjectAuthID)
	return a == nil && s == nil && strings.TrimSpace(c.ActorAuthID) == c.ActorAuthID && strings.TrimSpace(c.SubjectAuthID) == c.SubjectAuthID && (c.Action == "SUSPEND" || c.Action == "RESTORE") && c.ExpectedRevision > 0 && c.Reason != "" && strings.TrimSpace(c.Reason) == c.Reason && len(c.Reason) <= 1024 && utf8.ValidString(c.Reason)
}
func ChangeDeveloperStatus(s ManagedDeveloperState, c ManageDeveloperCommand, verifiedEmail, recoveryReady bool, now time.Time) (ManagedDeveloperState, error) {
	if !s.Valid() {
		return ManagedDeveloperState{}, ErrManagementUnavailable
	}
	if s.Revision != c.ExpectedRevision {
		return ManagedDeveloperState{}, ErrManagementConflict
	}
	next := ""
	switch c.Action {
	case "SUSPEND":
		if s.Status != "APPROVED" {
			return ManagedDeveloperState{}, ErrManagementConflict
		}
		next = "SUSPENDED"
	case "RESTORE":
		if s.Status != "SUSPENDED" {
			return ManagedDeveloperState{}, ErrManagementConflict
		}
		if !verifiedEmail || !recoveryReady {
			return ManagedDeveloperState{}, ErrRestoreBlocked
		}
		next = "APPROVED"
	default:
		return ManagedDeveloperState{}, ErrManagementInvalid
	}
	if s.Revision == math.MaxInt64 {
		return ManagedDeveloperState{}, ErrDeveloperRevisionExhausted
	}
	out := s
	out.Status = next
	out.Revision++
	out.StatusChangedAt = &now
	return out, nil
}
