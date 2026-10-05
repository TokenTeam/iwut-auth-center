package domain

import (
	"errors"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const Manager = "auth.platform-admin.manage"

func Permissions() []string {
	return []string{"auth.account.manage", "auth.developer.manage", Manager, "auth.reviewer.manage"}
}

var (
	ErrInvalid           = errors.New("INVALID_PLATFORM_ADMIN_REQUEST")
	ErrForbidden         = errors.New("PLATFORM_ADMIN_FORBIDDEN")
	ErrSubject           = errors.New("PLATFORM_ADMIN_SUBJECT_UNAVAILABLE")
	ErrConflict          = errors.New("PLATFORM_ADMIN_CONFLICT")
	ErrGrantBlocked      = errors.New("PLATFORM_ADMIN_GRANT_BLOCKED")
	ErrLast              = errors.New("LAST_PLATFORM_ADMIN_REQUIRED")
	ErrExhausted         = errors.New("PERMISSION_REVISION_EXHAUSTED")
	ErrRate              = errors.New("PLATFORM_ADMIN_RATE_LIMITED")
	ErrUnavailable       = errors.New("PLATFORM_ADMIN_UNAVAILABLE")
	ErrBootstrapConsumed = errors.New("PLATFORM_ADMIN_BOOTSTRAP_CONSUMED")
)
var Errors = []error{ErrInvalid, ErrForbidden, ErrSubject, ErrConflict, ErrGrantBlocked, ErrLast, ErrExhausted, ErrRate, ErrUnavailable, ErrBootstrapConsumed}

type Blocked struct{ Blocker string }

func (e *Blocked) Error() string { return ErrGrantBlocked.Error() }
func (e *Blocked) Unwrap() error { return ErrGrantBlocked }
func ValidID(s string) bool {
	return s != "" && len(s) <= 256 && strings.TrimSpace(s) == s && utf8.ValidString(s)
}
func Membership(permissions []string) (bool, error) {
	if permissions == nil {
		return false, ErrUnavailable
	}
	seen := map[string]bool{}
	count := 0
	for _, p := range permissions {
		if p == "" || strings.TrimSpace(p) != p || seen[p] {
			return false, ErrUnavailable
		}
		seen[p] = true
		if slices.Contains(Permissions(), p) {
			count++
		}
	}
	if count != 0 && count != 4 {
		return false, ErrUnavailable
	}
	return count == 4, nil
}

type State struct {
	AuthID, AccountStatus string
	Granted               bool
	Revision              int64
	Blockers              []string
}

func (s State) Effective() bool { return s.Granted && s.AccountStatus == "ACTIVE" }

type Snapshot struct {
	AuthID, AccountStatus        string
	Permissions                  []string
	Revision                     int64
	EmailVerified, RecoveryReady bool
}

func (s Snapshot) State() (State, error) {
	g, e := Membership(s.Permissions)
	if e != nil || !ValidID(s.AuthID) || s.Revision <= 0 || (s.AccountStatus != "ACTIVE" && s.AccountStatus != "DISABLED") {
		return State{}, ErrUnavailable
	}
	out := State{s.AuthID, s.AccountStatus, g, s.Revision, []string{}}
	if g {
		out.Blockers = append(out.Blockers, "ALREADY_GRANTED")
	}
	if s.AccountStatus == "DISABLED" {
		out.Blockers = append(out.Blockers, "ACCOUNT_DISABLED")
	}
	if !s.EmailVerified {
		out.Blockers = append(out.Blockers, "EMAIL_REQUIRED")
	}
	if !s.RecoveryReady {
		out.Blockers = append(out.Blockers, "EMAIL_RECOVERY_UNAVAILABLE")
	}
	return out, nil
}

type Command struct {
	ActorAuthID, SubjectAuthID, Action, Reason string
	ExpectedRevision                           int64
}

func (c Command) Valid() bool {
	return ValidID(c.ActorAuthID) && ValidID(c.SubjectAuthID) && (c.Action == "GRANT" || c.Action == "REVOKE") && c.ExpectedRevision > 0 && len(c.Reason) > 0 && len(c.Reason) <= 1024 && strings.TrimSpace(c.Reason) == c.Reason && utf8.ValidString(c.Reason)
}
func Change(s Snapshot, c Command) (Snapshot, error) {
	state, err := s.State()
	if err != nil {
		return Snapshot{}, err
	}
	if s.Revision != c.ExpectedRevision {
		return Snapshot{}, ErrConflict
	}
	if c.Action == "GRANT" {
		if state.Granted {
			return Snapshot{}, ErrConflict
		}
		if len(state.Blockers) > 0 {
			return Snapshot{}, &Blocked{state.Blockers[0]}
		}
	} else if c.Action == "REVOKE" {
		if !state.Granted {
			return Snapshot{}, ErrConflict
		}
	} else {
		return Snapshot{}, ErrInvalid
	}
	if s.Revision == math.MaxInt64 {
		return Snapshot{}, ErrExhausted
	}
	out := s
	out.Revision++
	out.Permissions = []string{}
	for _, p := range s.Permissions {
		if !slices.Contains(Permissions(), p) {
			out.Permissions = append(out.Permissions, p)
		}
	}
	if c.Action == "GRANT" {
		out.Permissions = append(out.Permissions, Permissions()...)
	}
	slices.Sort(out.Permissions)
	return out, nil
}

type Page struct {
	Items           []State
	NextAfterAuthID string
	ObservedAt      time.Time
}
type BootstrapResult struct {
	Applied bool
	EventID string
}
