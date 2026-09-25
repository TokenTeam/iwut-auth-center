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
		v, e := s.Apply(tc.ready)
		if v != tc.activate || !errors.Is(e, tc.err) || !reflect.DeepEqual(s.Blockers(tc.ready), tc.blockers) {
			t.Fatal(tc, v, e, s.Blockers(tc.ready))
		}
	}
	at := time.Now()
	for _, s := range []ApplicationState{{AuthID: "u", Status: "UNKNOWN"}, {AuthID: "u", ActivatedAt: &at}, {AuthID: "u", EmailRevision: -1}, {}} {
		if _, e := s.Apply(true); !errors.Is(e, ErrApplicationUnavailable) {
			t.Fatal(s, e)
		}
	}
}
