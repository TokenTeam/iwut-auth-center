package domain

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestApplicationTransitionsAndBlockers(t *testing.T) {
	for _, tc := range []struct {
		status   DeveloperStatus
		email    int64
		ready    bool
		activate bool
		err      error
		blockers []ApplicationBlocker
	}{
		{"", 0, false, false, ErrEmailRequired, []ApplicationBlocker{EmailRequired, EmailLoginUnavailable}},
		{"", 1, false, false, ErrEmailLoginUnavailable, []ApplicationBlocker{EmailLoginUnavailable}},
		{"", 0, true, false, ErrEmailRequired, []ApplicationBlocker{EmailRequired}},
		{"", 1, true, true, nil, []ApplicationBlocker{}},
		{DeveloperStatusApproved, 0, false, false, nil, []ApplicationBlocker{AlreadyDeveloper}},
		{DeveloperStatusPending, 1, true, false, ErrApplicationExists, []ApplicationBlocker{ExistingApplication}},
		{DeveloperStatusRejected, 1, true, false, ErrReapplication, []ApplicationBlocker{ReapplicationNotAllowed}},
		{DeveloperStatusSuspended, 1, true, false, ErrReapplication, []ApplicationBlocker{ReapplicationNotAllowed}},
	} {
		s := ApplicationState{AuthID: "u", Status: tc.status, EmailRevision: tc.email}
		if s.Status == DeveloperStatusApproved {
			s.DeveloperHandle = "alice"
		}
		v, e := s.Apply(tc.ready, "Alice")
		if v != tc.activate || !errors.Is(e, tc.err) || !reflect.DeepEqual(s.Blockers(tc.ready), tc.blockers) {
			t.Fatal(tc, v, e, s.Blockers(tc.ready))
		}
	}
	at := time.Now()
	for _, s := range []ApplicationState{{AuthID: "u", Status: "UNKNOWN"}, {AuthID: "u", ActivatedAt: &at}, {AuthID: "u", EmailRevision: -1}, {}} {
		if _, e := s.Apply(true, "Alice"); !errors.Is(e, ErrApplicationUnavailable) {
			t.Fatal(s, e)
		}
	}
}

func TestDeveloperHandleNormalizationAndRequiredInput(t *testing.T) {
	for raw, want := range map[string]string{"Alice": "alice", "abc": "abc", "A_-": "a_-", "OFFICIAL": "official", "Admin": "admin", "abcdefghijklmnopqrstuvwxyz123456": "abcdefghijklmnopqrstuvwxyz123456"} {
		got, e := NormalizeDeveloperHandle(raw)
		if e != nil || got != want {
			t.Fatal(raw, got, e)
		}
	}
	for _, raw := range []string{"", "ab", "1alice", "_alice", "-alice", " Alice", "Alice ", "ali ce", "alice/name", "alice.name", "爱丽丝", "Ａlice", "alicé", "abcdefghijklmnopqrstuvwxyz1234567"} {
		if _, e := NormalizeDeveloperHandle(raw); !errors.Is(e, ErrInvalidHandle) {
			t.Fatal(raw, e)
		}
		s := ApplicationState{AuthID: "u", Status: DeveloperStatusApproved, DeveloperHandle: "alice"}
		if _, e := s.Apply(false, raw); !errors.Is(e, ErrInvalidHandle) {
			t.Fatal("approved bypassed required input", raw, e)
		}
	}
	s := ApplicationState{AuthID: "u", Status: DeveloperStatusApproved, DeveloperHandle: "alice"}
	if claim, e := s.Apply(false, "ALICE"); e != nil || claim {
		t.Fatal(claim, e)
	}
	if _, e := s.Apply(true, "Bob"); !errors.Is(e, ErrHandleChange) {
		t.Fatal(e)
	}
}
func TestHistoricalApprovedNeedsEmailAndRecoveryForHandle(t *testing.T) {
	s := ApplicationState{AuthID: "u", Status: DeveloperStatusApproved}
	if _, e := s.Apply(false, "Alice"); !errors.Is(e, ErrEmailRequired) {
		t.Fatal(e)
	}
	if got := s.Blockers(false); !reflect.DeepEqual(got, []ApplicationBlocker{EmailRequired, EmailLoginUnavailable}) {
		t.Fatal(got)
	}
	s.EmailRevision = 1
	if _, e := s.Apply(false, "Alice"); !errors.Is(e, ErrEmailLoginUnavailable) {
		t.Fatal(e)
	}
	if claim, e := s.Apply(true, "Alice"); e != nil || !claim || len(s.Blockers(true)) != 0 {
		t.Fatal(claim, e)
	}
	for _, status := range []DeveloperStatus{DeveloperStatusPending, DeveloperStatusRejected, DeveloperStatusSuspended} {
		s.Status = status
		if _, e := s.Apply(true, "Alice"); e == nil {
			t.Fatal(status)
		}
	}
}
