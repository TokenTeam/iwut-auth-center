package domain

import (
	"errors"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

const ProfileReviewer = "app.profile.review"
const Reviewer = "app.version.review"
const Manager = "auth.reviewer.manage"

var (
	ErrInvalid           = errors.New("INVALID_REVIEWER_PERMISSION_INPUT")
	ErrForbidden         = errors.New("REVIEWER_MANAGEMENT_FORBIDDEN")
	ErrSubject           = errors.New("REVIEWER_SUBJECT_UNAVAILABLE")
	ErrConflict          = errors.New("REVIEWER_PERMISSION_CONFLICT")
	ErrExhausted         = errors.New("PERMISSION_REVISION_EXHAUSTED")
	ErrUnavailable       = errors.New("REVIEWER_PERMISSION_UNAVAILABLE")
	ErrBootstrapConsumed = errors.New("PLATFORM_ADMIN_BOOTSTRAP_CONSUMED")
)

type State struct {
	AuthID      string
	Permissions []string
	Revision    int64
}

func (s State) Valid() bool {
	if !ValidID(s.AuthID) || s.Revision <= 0 || s.Permissions == nil {
		return false
	}
	seen := map[string]bool{}
	for _, p := range s.Permissions {
		if p == "" || strings.TrimSpace(p) != p || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}
func ValidID(s string) bool {
	return s != "" && len(s) <= 256 && strings.TrimSpace(s) == s && utf8.ValidString(s)
}
func (s State) Has(p string) bool { return slices.Contains(s.Permissions, p) }

type Command struct {
	ActorAuthID, SubjectAuthID, Permission, Action, Reason string
	ExpectedRevision                                       int64
}

func (c Command) Valid() bool {
	return (c.Permission == ProfileReviewer || c.Permission == Reviewer) && ValidID(c.ActorAuthID) && ValidID(c.SubjectAuthID) && (c.Action == "GRANT" || c.Action == "REVOKE") && c.ExpectedRevision > 0 && strings.TrimSpace(c.Reason) != "" && len(c.Reason) <= 1024 && utf8.ValidString(c.Reason)
}
func Change(s State, permission, action string, revision int64) (State, error) {
	if !s.Valid() {
		return State{}, ErrUnavailable
	}
	if s.Revision != revision || (action == "GRANT") == s.Has(permission) {
		return State{}, ErrConflict
	}
	if s.Revision == math.MaxInt64 {
		return State{}, ErrExhausted
	}
	next := State{AuthID: s.AuthID, Revision: s.Revision + 1, Permissions: []string{}}
	for _, p := range s.Permissions {
		if p != permission {
			next.Permissions = append(next.Permissions, p)
		}
	}
	if action == "GRANT" {
		next.Permissions = append(next.Permissions, permission)
	}
	slices.Sort(next.Permissions)
	return next, nil
}
