package domain

import (
	"errors"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

const Suspend = "app.application.suspend"
const Restore = "app.application.restore"

func Permissions() []string { return []string{Restore, Suspend} }

var (
	ErrIdentity     = errors.New("INVALID_USER_IDENTITY")
	ErrInvalid      = errors.New("INVALID_APPLICATION_OPERATIONS_PERMISSION_REQUEST")
	ErrForbidden    = errors.New("APPLICATION_OPERATIONS_PERMISSION_FORBIDDEN")
	ErrSubject      = errors.New("APPLICATION_OPERATIONS_PERMISSION_SUBJECT_UNAVAILABLE")
	ErrConflict     = errors.New("APPLICATION_OPERATIONS_PERMISSION_CONFLICT")
	ErrGrantBlocked = errors.New("APPLICATION_OPERATIONS_PERMISSION_GRANT_BLOCKED")
	ErrExhausted    = errors.New("PERMISSION_REVISION_EXHAUSTED")
	ErrRate         = errors.New("APPLICATION_OPERATIONS_PERMISSION_RATE_LIMITED")
	ErrUnavailable  = errors.New("APPLICATION_OPERATIONS_PERMISSION_UNAVAILABLE")
)

type Blocked struct{ Blocker string }

func (e *Blocked) Error() string { return ErrGrantBlocked.Error() }
func (e *Blocked) Unwrap() error { return ErrGrantBlocked }

func ValidID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && utf8.ValidString(value)
}

func ValidPermission(value string) bool { return slices.Contains(Permissions(), value) }

type Permission struct {
	Name      string
	Granted   bool
	Effective bool
}

type State struct {
	AuthID, AccountStatus string
	Permissions           []Permission
	Revision              int64
	GrantBlockers         []string
}

func (s State) Has(permission string) bool {
	for _, item := range s.Permissions {
		if item.Name == permission {
			return item.Granted
		}
	}
	return false
}

type Snapshot struct {
	AuthID, AccountStatus        string
	Permissions                  []string
	Revision                     int64
	EmailVerified, RecoveryReady bool
}

func (s Snapshot) State() (State, error) {
	if !ValidID(s.AuthID) || s.Revision <= 0 || (s.AccountStatus != "ACTIVE" && s.AccountStatus != "DISABLED") || s.Permissions == nil {
		return State{}, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, permission := range s.Permissions {
		if permission == "" || strings.TrimSpace(permission) != permission || seen[permission] {
			return State{}, ErrUnavailable
		}
		seen[permission] = true
	}
	out := State{AuthID: s.AuthID, AccountStatus: s.AccountStatus, Revision: s.Revision, Permissions: []Permission{}, GrantBlockers: []string{}}
	for _, permission := range Permissions() {
		granted := seen[permission]
		out.Permissions = append(out.Permissions, Permission{Name: permission, Granted: granted, Effective: granted && s.AccountStatus == "ACTIVE"})
	}
	if s.AccountStatus == "DISABLED" {
		out.GrantBlockers = append(out.GrantBlockers, "ACCOUNT_DISABLED")
	}
	if !s.EmailVerified {
		out.GrantBlockers = append(out.GrantBlockers, "EMAIL_REQUIRED")
	}
	if !s.RecoveryReady {
		out.GrantBlockers = append(out.GrantBlockers, "EMAIL_RECOVERY_UNAVAILABLE")
	}
	return out, nil
}

type Command struct {
	ActorAuthID, SubjectAuthID, Permission, Action, Reason string
	ExpectedRevision                                       int64
}

func (c Command) Valid() bool {
	return ValidID(c.ActorAuthID) && ValidID(c.SubjectAuthID) && ValidPermission(c.Permission) &&
		(c.Action == "GRANT" || c.Action == "REVOKE") && c.ExpectedRevision > 0 &&
		len(c.Reason) > 0 && len(c.Reason) <= 1024 && strings.TrimSpace(c.Reason) == c.Reason && utf8.ValidString(c.Reason)
}

func Change(s Snapshot, c Command) (Snapshot, error) {
	state, err := s.State()
	if err != nil {
		return Snapshot{}, err
	}
	if !ValidPermission(c.Permission) || (c.Action != "GRANT" && c.Action != "REVOKE") {
		return Snapshot{}, ErrInvalid
	}
	if s.Revision != c.ExpectedRevision || (c.Action == "GRANT") == state.Has(c.Permission) {
		return Snapshot{}, ErrConflict
	}
	if c.Action == "GRANT" && len(state.GrantBlockers) > 0 {
		return Snapshot{}, &Blocked{Blocker: state.GrantBlockers[0]}
	}
	if s.Revision == math.MaxInt64 {
		return Snapshot{}, ErrExhausted
	}
	out := s
	out.Revision++
	out.Permissions = []string{}
	for _, permission := range s.Permissions {
		if permission != c.Permission {
			out.Permissions = append(out.Permissions, permission)
		}
	}
	if c.Action == "GRANT" {
		out.Permissions = append(out.Permissions, c.Permission)
	}
	slices.Sort(out.Permissions)
	return out, nil
}
