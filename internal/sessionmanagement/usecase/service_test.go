package usecase

import (
	"context"
	"errors"
	d "iwut-auth-center/internal/sessionmanagement/domain"
	"testing"
	"time"
)

const testID = "11111111-1111-4111-8111-111111111111"

type fake struct {
	authCalls, listCalls, revokeCalls, limits, ids int
	allowed                                        bool
	authErr, errorFinal                            error
	gotID                                          string
	now                                            time.Time
}

func (f *fake) Authenticate(context.Context, []byte, time.Time) (string, error) {
	f.authCalls++
	return "owner", f.authErr
}
func (f *fake) List(_ context.Context, _ []byte, _ int, _ string, now time.Time) (d.Page, error) {
	f.listCalls++
	f.now = now
	return d.Page{}, f.errorFinal
}
func (f *fake) Revoke(_ context.Context, _ []byte, _ []string, id string, now time.Time) error {
	f.revokeCalls++
	f.gotID = id
	f.now = now
	return f.errorFinal
}
func (f *fake) AllowAccount(id string, _ time.Time) bool {
	if id != "owner" {
		panic("untrusted account")
	}
	f.limits++
	return f.allowed
}
func (f *fake) NewID() (string, error) { f.ids++; return testID, nil }
func TestServiceValidationAuthenticationAndSingleAdmission(t *testing.T) {
	f := &fake{allowed: true}
	s, _ := New(f, f, f)
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	for _, size := range []int{0, 51, -1} {
		if _, e := s.List(t.Context(), make([]byte, 32), size, ""); !errors.Is(e, d.ErrInvalidRequest) {
			t.Fatal(e)
		}
	}
	for _, ids := range [][]string{nil, {testID, testID}, {"bad"}} {
		if e := s.Revoke(t.Context(), make([]byte, 32), ids); !errors.Is(e, d.ErrInvalidRequest) {
			t.Fatal(e)
		}
	}
	if f.authCalls != 0 || f.limits != 0 {
		t.Fatal("invalid input consumed account allowance")
	}
	f.authErr = d.ErrSessionInvalid
	if _, e := s.List(t.Context(), make([]byte, 32), 10, ""); !errors.Is(e, d.ErrSessionInvalid) {
		t.Fatal(e)
	}
	if f.limits != 0 {
		t.Fatal("failed authentication consumed allowance")
	}
	f.authErr = nil
	f.allowed = false
	if e := s.Revoke(t.Context(), make([]byte, 32), []string{testID}); !errors.Is(e, d.ErrRateLimited) {
		t.Fatal(e)
	}
	if f.revokeCalls != 0 || f.ids != 0 {
		t.Fatal("limited request mutated")
	}
	f.allowed = true
	f.errorFinal = d.ErrSessionInvalid
	if e := s.Revoke(t.Context(), make([]byte, 32), []string{testID}); !errors.Is(e, d.ErrSessionInvalid) {
		t.Fatal("final recheck bypassed", e)
	}
	if f.limits != 2 || f.ids != 1 || f.revokeCalls != 1 || f.gotID != testID || !f.now.Equal(now) {
		t.Fatal(f)
	}
}
