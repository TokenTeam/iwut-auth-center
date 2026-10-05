package domain

import (
	"errors"
	"math"
	"slices"
	"testing"
)

func TestBundleTransitionsPreserveOtherCapabilities(t *testing.T) {
	before := Snapshot{AuthID: "user", AccountStatus: "ACTIVE", Permissions: []string{"app.profile.review", "app.version.review", "other"}, Revision: 4, EmailVerified: true, RecoveryReady: true}
	granted, e := Change(before, Command{Action: "GRANT", ExpectedRevision: 4})
	if e != nil || granted.Revision != 5 || len(granted.Permissions) != 7 {
		t.Fatal(granted, e)
	}
	revoked, e := Change(granted, Command{Action: "REVOKE", ExpectedRevision: 5})
	if e != nil || !slices.Equal(revoked.Permissions, before.Permissions) || revoked.Revision != 6 {
		t.Fatal(revoked, e)
	}
	for _, p := range [][]string{nil, {Manager}, {"auth.reviewer.manage"}, {Manager, Manager}, {"bad "}} {
		if _, e := Membership(p); !errors.Is(e, ErrUnavailable) {
			t.Fatal(p, e)
		}
	}
	for _, tc := range []struct {
		edit func(*Snapshot)
		want error
	}{{func(s *Snapshot) { s.AccountStatus = "DISABLED" }, ErrGrantBlocked}, {func(s *Snapshot) { s.EmailVerified = false }, ErrGrantBlocked}, {func(s *Snapshot) { s.RecoveryReady = false }, ErrGrantBlocked}, {func(s *Snapshot) { s.Revision = math.MaxInt64 }, ErrExhausted}} {
		s := before
		tc.edit(&s)
		if _, e := Change(s, Command{Action: "GRANT", ExpectedRevision: s.Revision}); !errors.Is(e, tc.want) {
			t.Fatal(e)
		}
	}
	granted.AccountStatus = "DISABLED"
	granted.EmailVerified = false
	granted.RecoveryReady = false
	if _, e := Change(granted, Command{Action: "REVOKE", ExpectedRevision: 5}); e != nil {
		t.Fatal(e)
	}
	if _, e := Change(before, Command{Action: "GRANT", ExpectedRevision: 3}); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestBlockersAreStableAndComplete(t *testing.T) {
	s, e := (Snapshot{AuthID: "u", AccountStatus: "DISABLED", Permissions: Permissions(), Revision: 1}).State()
	if e != nil || s.Effective() || !slices.Equal(s.Blockers, []string{"ALREADY_GRANTED", "ACCOUNT_DISABLED", "EMAIL_REQUIRED", "EMAIL_RECOVERY_UNAVAILABLE"}) {
		t.Fatal(s, e)
	}
}
