package domain

import (
	"errors"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	MaintainPermission = "app.script.maintain"
	ReviewPermission   = "app.script.review"
	PublishPermission  = "app.script.publish"
	SuspendPermission  = "app.script.suspend"
	RestorePermission  = "app.script.restore"
)

var permissions = [...]string{MaintainPermission, ReviewPermission, PublishPermission, SuspendPermission, RestorePermission}

func KnownPermission(id string) bool { return slices.Contains(permissions[:], id) }

var (
	ErrIdentity     = errors.New("INVALID_USER_IDENTITY")
	ErrInvalid      = errors.New("INVALID_SCRIPT_MAINTAINER_PERMISSION_REQUEST")
	ErrForbidden    = errors.New("SCRIPT_MAINTAINER_PERMISSION_FORBIDDEN")
	ErrSubject      = errors.New("SCRIPT_MAINTAINER_PERMISSION_SUBJECT_UNAVAILABLE")
	ErrConflict     = errors.New("SCRIPT_MAINTAINER_PERMISSION_CONFLICT")
	ErrGrantBlocked = errors.New("SCRIPT_MAINTAINER_PERMISSION_GRANT_BLOCKED")
	ErrExhausted    = errors.New("PERMISSION_REVISION_EXHAUSTED")
	ErrRate         = errors.New("SCRIPT_MAINTAINER_PERMISSION_RATE_LIMITED")
	ErrUnavailable  = errors.New("SCRIPT_MAINTAINER_PERMISSION_UNAVAILABLE")
)

type PermissionState struct {
	ID                 string
	Granted, Effective bool
}

type State struct {
	AuthID      string
	Revision    int64
	Permissions [len(permissions)]PermissionState
}

func (s State) For(id string) PermissionState {
	for _, permission := range s.Permissions {
		if permission.ID == id {
			return permission
		}
	}
	return PermissionState{}
}

type Snapshot struct {
	AuthID, AccountStatus string
	Permissions           []string
	Revision              int64
}

type Command struct {
	ActorAuthID, SubjectAuthID, Permission, Action, Reason string
	ExpectedRevision                                       int64
}

func ValidID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && utf8.ValidString(value)
}

func (c Command) Valid() bool {
	return ValidID(c.ActorAuthID) && ValidID(c.SubjectAuthID) && KnownPermission(c.Permission) && (c.Action == "GRANT" || c.Action == "REVOKE") &&
		c.ExpectedRevision > 0 && len(c.Reason) > 0 && len(c.Reason) <= 1024 && strings.TrimSpace(c.Reason) == c.Reason && utf8.ValidString(c.Reason)
}

func (s Snapshot) State() (State, error) {
	if !ValidID(s.AuthID) || s.Revision <= 0 || s.Permissions == nil || (s.AccountStatus != "ACTIVE" && s.AccountStatus != "DISABLED") {
		return State{}, ErrUnavailable
	}
	seen := make(map[string]bool, len(s.Permissions))
	for _, id := range s.Permissions {
		if id == "" || !utf8.ValidString(id) || strings.TrimSpace(id) != id || seen[id] {
			return State{}, ErrUnavailable
		}
		seen[id] = true
	}
	state := State{AuthID: s.AuthID, Revision: s.Revision}
	for i, id := range permissions {
		granted := seen[id]
		state.Permissions[i] = PermissionState{ID: id, Granted: granted, Effective: granted && s.AccountStatus == "ACTIVE"}
	}
	return state, nil
}

// Change builds the single-permission CAS candidate. The repository checks
// email recovery for a grant only, in the same transaction before writing it.
func Change(s Snapshot, c Command) (Snapshot, error) {
	if !c.Valid() || c.SubjectAuthID != s.AuthID {
		return Snapshot{}, ErrInvalid
	}
	state, err := s.State()
	if err != nil {
		return Snapshot{}, err
	}
	grant := c.Action == "GRANT"
	if s.Revision != c.ExpectedRevision || grant == state.For(c.Permission).Granted {
		return Snapshot{}, ErrConflict
	}
	if grant && s.AccountStatus != "ACTIVE" {
		return Snapshot{}, ErrGrantBlocked
	}
	if s.Revision == math.MaxInt64 {
		return Snapshot{}, ErrExhausted
	}
	out := s
	out.Revision++
	out.Permissions = make([]string, 0, len(s.Permissions)+1)
	for _, id := range s.Permissions {
		if id != c.Permission {
			out.Permissions = append(out.Permissions, id)
		}
	}
	if grant {
		out.Permissions = append(out.Permissions, c.Permission)
	}
	slices.Sort(out.Permissions)
	return out, nil
}
