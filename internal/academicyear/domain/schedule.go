package domain

import (
	"errors"
	"math"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode/utf8"
)

var (
	ErrIdentity          = errors.New("INVALID_USER_IDENTITY")
	ErrInvalid           = errors.New("INVALID_ACADEMIC_YEAR_POLICY_REQUEST")
	ErrForbidden         = errors.New("ACADEMIC_YEAR_POLICY_FORBIDDEN")
	ErrNotFuture         = errors.New("ACADEMIC_YEAR_ROLLOVER_NOT_FUTURE")
	ErrConflict          = errors.New("ACADEMIC_YEAR_POLICY_CONFLICT")
	ErrRevisionExhausted = errors.New("ACADEMIC_YEAR_POLICY_REVISION_EXHAUSTED")
	ErrRangeExhausted    = errors.New("ACADEMIC_YEAR_RANGE_EXHAUSTED")
	ErrRate              = errors.New("ACADEMIC_YEAR_POLICY_RATE_LIMITED")
	ErrUnavailable       = errors.New("ACADEMIC_YEAR_POLICY_UNAVAILABLE")
)

var Errors = []error{ErrIdentity, ErrInvalid, ErrForbidden, ErrNotFuture, ErrConflict, ErrRevisionExhausted, ErrRangeExhausted, ErrRate, ErrUnavailable}

var shanghai = mustShanghai()

func mustShanghai() *time.Location {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		panic(err)
	}
	return location
}

type State struct {
	AnchorAt           time.Time
	AnchorAcademicYear int32
	Revision           int64
	UpdatedAt          time.Time
	UpdatedByAuthID    string
}

type Schedule struct {
	CurrentAcademicYear int32
	NextRolloverAt      time.Time
	ObservedAt          time.Time
	Revision            int64
	UpdatedAt           time.Time
	UpdatedByAuthID     string
}

type Command struct {
	ActorAuthID      string
	NextRolloverAt   time.Time
	ExpectedRevision int64
	Reason           string
}

func DefaultState() State {
	anchor := time.Date(1970, time.September, 1, 0, 0, 0, 0, shanghai)
	return State{AnchorAt: anchor.UTC(), AnchorAcademicYear: 1970, Revision: 1, UpdatedAt: anchor.UTC()}
}

func ValidAuthID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && utf8.ValidString(value)
}

func (command Command) Valid() bool {
	return ValidAuthID(command.ActorAuthID) && validInstant(command.NextRolloverAt) && command.ExpectedRevision > 0 && len(command.Reason) > 0 && len(command.Reason) <= 1024 && strings.TrimSpace(command.Reason) == command.Reason && utf8.ValidString(command.Reason)
}

func (state State) Valid() bool {
	if !validInstant(state.AnchorAt) || state.AnchorAcademicYear <= 0 || state.AnchorAcademicYear >= math.MaxInt32 || state.Revision <= 0 || !validInstant(state.UpdatedAt) || state.UpdatedByAuthID != "" && !ValidAuthID(state.UpdatedByAuthID) {
		return false
	}
	_, err := occurrence(state.AnchorAt, 1)
	return err == nil
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999
}

// occurrence returns a recurrence in constant time. A February 29 anchor
// permanently becomes March 1 after its first non-leap recurrence.
func occurrence(anchor time.Time, offset int64) (time.Time, error) {
	if offset < 0 {
		return time.Time{}, ErrRangeExhausted
	}
	local := anchor.In(shanghai)
	year := int64(local.Year()) + offset
	if year < 1 || year > 9999 {
		return time.Time{}, ErrRangeExhausted
	}
	month, day := local.Month(), local.Day()
	if month == time.February && day == 29 && offset > 0 {
		month, day = time.March, 1
	}
	value := time.Date(int(year), month, day, local.Hour(), local.Minute(), local.Second(), local.Nanosecond(), shanghai)
	if value.Year() != int(year) || value.Month() != month || value.Day() != day {
		return time.Time{}, ErrRangeExhausted
	}
	return value.UTC(), nil
}

func Project(state State, observedAt time.Time) (Schedule, error) {
	if !state.Valid() || !validInstant(observedAt) {
		return Schedule{}, ErrUnavailable
	}
	anchor := state.AnchorAt.UTC()
	observedAt = observedAt.UTC()
	if observedAt.Before(anchor) {
		if state.AnchorAcademicYear <= 1 {
			return Schedule{}, ErrRangeExhausted
		}
		return Schedule{CurrentAcademicYear: state.AnchorAcademicYear - 1, NextRolloverAt: anchor, ObservedAt: observedAt, Revision: state.Revision, UpdatedAt: state.UpdatedAt.UTC(), UpdatedByAuthID: state.UpdatedByAuthID}, nil
	}

	offset := int64(observedAt.In(shanghai).Year() - anchor.In(shanghai).Year())
	currentBoundary, err := occurrence(anchor, offset)
	if err != nil {
		return Schedule{}, err
	}
	if currentBoundary.After(observedAt) {
		offset--
		currentBoundary, err = occurrence(anchor, offset)
		if err != nil {
			return Schedule{}, err
		}
	}
	next, err := occurrence(anchor, offset+1)
	if err != nil {
		return Schedule{}, err
	}
	if !next.After(observedAt) {
		offset++
		next, err = occurrence(anchor, offset+1)
		if err != nil {
			return Schedule{}, err
		}
	}
	academicYear := int64(state.AnchorAcademicYear) + offset
	if academicYear <= 0 || academicYear > math.MaxInt32 || !next.After(observedAt) {
		return Schedule{}, ErrRangeExhausted
	}
	return Schedule{CurrentAcademicYear: int32(academicYear), NextRolloverAt: next, ObservedAt: observedAt, Revision: state.Revision, UpdatedAt: state.UpdatedAt.UTC(), UpdatedByAuthID: state.UpdatedByAuthID}, nil
}

func Change(state State, command Command, now time.Time) (State, Schedule, bool, error) {
	if !command.Valid() || !validInstant(now) {
		return State{}, Schedule{}, false, ErrInvalid
	}
	command.NextRolloverAt = command.NextRolloverAt.UTC()
	now = now.UTC()
	if !command.NextRolloverAt.After(now) {
		return State{}, Schedule{}, false, ErrNotFuture
	}
	before, err := Project(state, now)
	if err != nil {
		return State{}, Schedule{}, false, err
	}
	if command.ExpectedRevision != state.Revision {
		return State{}, Schedule{}, false, ErrConflict
	}
	if command.NextRolloverAt.Equal(before.NextRolloverAt) {
		return state, before, false, nil
	}
	if state.Revision == math.MaxInt64 {
		return State{}, Schedule{}, false, ErrRevisionExhausted
	}
	if before.CurrentAcademicYear >= math.MaxInt32-1 || command.NextRolloverAt.In(shanghai).Year() >= 9999 {
		return State{}, Schedule{}, false, ErrRangeExhausted
	}
	after := State{AnchorAt: command.NextRolloverAt, AnchorAcademicYear: before.CurrentAcademicYear + 1, Revision: state.Revision + 1, UpdatedAt: now, UpdatedByAuthID: command.ActorAuthID}
	projected, err := Project(after, now)
	if err != nil {
		return State{}, Schedule{}, false, err
	}
	return after, projected, true, nil
}
