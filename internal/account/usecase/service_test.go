package usecase

import (
	"context"
	"errors"
	d "iwut-auth-center/internal/account/domain"
	"testing"
	"time"
)

type repository struct {
	calls   int
	command d.Command
}

func (r *repository) Get(context.Context, string, string) (d.State, error) {
	r.calls++
	return d.State{}, nil
}
func (r *repository) Manage(_ context.Context, c d.Command) (d.State, error) {
	r.calls++
	r.command = c
	return d.State{}, nil
}
func TestAccountManagementValidationAndSeparateBoundedRateBuckets(t *testing.T) {
	r := &repository{}
	s := NewConfigured(r, 2, 1, 2)
	now := time.Now()
	s.now = func() time.Time { return now }
	ctx := context.Background()
	bad := d.Command{ActorAuthID: "a", SubjectAuthID: "u", ExpectedRevision: 1, Action: "INVALID", Reason: "x"}
	if _, err := s.Manage(ctx, bad); !errors.Is(err, d.ErrInvalid) || r.calls != 0 {
		t.Fatal(err)
	}
	c := bad
	c.Action = "DISABLE"
	c.Reason = "  test  "
	if _, err := s.Manage(ctx, c); err != nil || r.command.Reason != "test" {
		t.Fatal(err)
	}
	if _, err := s.Manage(ctx, c); !errors.Is(err, d.ErrRate) {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "a", "u"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "other", "u"); !errors.Is(err, d.ErrRate) {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := s.Get(ctx, "other", "u"); err != nil {
		t.Fatal(err)
	}
}
