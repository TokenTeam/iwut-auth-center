package domain

import (
	"errors"
	"math"
	"testing"
	"time"
)

func shanghaiTime(year int, month time.Month, day, hour int) time.Time {
	return time.Date(year, month, day, hour, 0, 0, 0, shanghai)
}

func TestDefaultProjection(t *testing.T) {
	before, err := Project(DefaultState(), shanghaiTime(2026, time.August, 31, 23))
	if err != nil || before.CurrentAcademicYear != 2025 || !before.NextRolloverAt.Equal(shanghaiTime(2026, time.September, 1, 0)) {
		t.Fatalf("before boundary: %#v, %v", before, err)
	}
	after, err := Project(DefaultState(), shanghaiTime(2026, time.October, 10, 0))
	if err != nil || after.CurrentAcademicYear != 2026 || !after.NextRolloverAt.Equal(shanghaiTime(2027, time.September, 1, 0)) {
		t.Fatalf("after boundary: %#v, %v", after, err)
	}
	exact, err := Project(DefaultState(), shanghaiTime(2026, time.September, 1, 0))
	if err != nil || exact.CurrentAcademicYear != 2026 || !exact.NextRolloverAt.Equal(shanghaiTime(2027, time.September, 1, 0)) {
		t.Fatalf("exact boundary: %#v, %v", exact, err)
	}
}

func TestLeapDayPermanentlyNormalizesToMarchFirst(t *testing.T) {
	state := State{AnchorAt: shanghaiTime(2028, time.February, 29, 0), AnchorAcademicYear: 2027, Revision: 2, UpdatedAt: shanghaiTime(2027, time.January, 1, 0), UpdatedByAuthID: "admin"}
	first, err := Project(state, shanghaiTime(2028, time.February, 29, 0))
	if err != nil || first.CurrentAcademicYear != 2027 || !first.NextRolloverAt.Equal(shanghaiTime(2029, time.March, 1, 0)) {
		t.Fatalf("first recurrence: %#v, %v", first, err)
	}
	later, err := Project(state, shanghaiTime(2032, time.February, 29, 12))
	if err != nil || later.CurrentAcademicYear != 2030 || !later.NextRolloverAt.Equal(shanghaiTime(2032, time.March, 1, 0)) {
		t.Fatalf("permanent normalization: %#v, %v", later, err)
	}
	beforeMarch, err := Project(state, shanghaiTime(2029, time.February, 28, 0))
	if err != nil || beforeMarch.CurrentAcademicYear != 2027 || !beforeMarch.NextRolloverAt.Equal(shanghaiTime(2029, time.March, 1, 0)) {
		t.Fatalf("before normalized boundary: %#v, %v", beforeMarch, err)
	}
}

func TestChangePreservesCurrentYearUntilFutureAnchor(t *testing.T) {
	now := shanghaiTime(2026, time.October, 10, 8)
	command := Command{ActorAuthID: "actor", NextRolloverAt: shanghaiTime(2027, time.February, 20, 0), ExpectedRevision: 1, Reason: "adjust schedule"}
	after, schedule, changed, err := Change(DefaultState(), command, now)
	if err != nil || !changed || schedule.CurrentAcademicYear != 2026 || schedule.Revision != 2 || !schedule.NextRolloverAt.Equal(command.NextRolloverAt) || after.AnchorAcademicYear != 2027 {
		t.Fatalf("change: %#v %#v %v %v", after, schedule, changed, err)
	}
}

func TestChangeValidationAndNoop(t *testing.T) {
	now := shanghaiTime(2026, time.October, 10, 8)
	schedule, _ := Project(DefaultState(), now)
	base := Command{ActorAuthID: "actor", NextRolloverAt: schedule.NextRolloverAt, ExpectedRevision: 1, Reason: "same"}
	_, _, changed, err := Change(DefaultState(), base, now)
	if err != nil || changed {
		t.Fatalf("no-op: changed=%v err=%v", changed, err)
	}
	base.ExpectedRevision = 2
	if _, _, _, err = Change(DefaultState(), base, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	base.ExpectedRevision = 1
	base.NextRolloverAt = now
	if _, _, _, err = Change(DefaultState(), base, now); !errors.Is(err, ErrNotFuture) {
		t.Fatalf("not future: %v", err)
	}
	exhausted := DefaultState()
	exhausted.Revision = math.MaxInt64
	base.NextRolloverAt = shanghaiTime(2027, time.October, 1, 0)
	base.ExpectedRevision = math.MaxInt64
	if _, _, _, err = Change(exhausted, base, now); !errors.Is(err, ErrRevisionExhausted) {
		t.Fatalf("revision exhaustion: %v", err)
	}
}

func TestStateRequiresRepresentableFollowingBoundary(t *testing.T) {
	state := State{AnchorAt: shanghaiTime(9999, time.January, 1, 0), AnchorAcademicYear: 9998, Revision: 2, UpdatedAt: shanghaiTime(9998, time.January, 1, 0), UpdatedByAuthID: "admin"}
	if state.Valid() {
		t.Fatal("state without representable following recurrence was accepted")
	}
	state = State{AnchorAt: shanghaiTime(2027, time.January, 1, 0), AnchorAcademicYear: math.MaxInt32, Revision: 2, UpdatedAt: shanghaiTime(2026, time.January, 1, 0), UpdatedByAuthID: "admin"}
	if state.Valid() {
		t.Fatal("state without representable following academic year was accepted")
	}
}
