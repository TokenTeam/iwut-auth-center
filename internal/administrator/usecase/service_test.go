package usecase

import (
	"context"
	"errors"
	d "iwut-auth-center/internal/administrator/domain"
	"testing"
	"time"
)

type repository struct {
	calls int
	last  d.Command
}

func (r *repository) Manage(_ context.Context, c d.Command) (d.State, error) {
	r.calls++
	r.last = c
	return d.State{}, nil
}
func (r *repository) Get(context.Context, string, string) (d.State, error) {
	r.calls++
	return d.State{}, nil
}
func (r *repository) List(context.Context, string, string, int) (d.Page, error) {
	r.calls++
	return d.Page{}, nil
}

type limiter struct{ reads, writes int }

func (l *limiter) AllowBegin(string, time.Time) bool    { l.reads++; return l.reads <= 2 }
func (l *limiter) AllowComplete(string, time.Time) bool { l.writes++; return l.writes <= 1 }
func TestLimitsSeparateReadsAndWritesAndValidateBeforeRepository(t *testing.T) {
	r, l := &repository{}, &limiter{}
	s := New(r, l)
	c := d.Command{ActorAuthID: "a", SubjectAuthID: "b", Action: "GRANT", Reason: "  reason  ", ExpectedRevision: 1}
	if _, e := s.Manage(t.Context(), c); e != nil || r.last.Reason != "reason" {
		t.Fatal(e, r.last)
	}
	if _, e := s.Manage(t.Context(), c); !errors.Is(e, d.ErrRate) {
		t.Fatal(e)
	}
	if _, e := s.List(t.Context(), "a", "", 20); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Get(t.Context(), "a", "b"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Get(t.Context(), "a", "b"); !errors.Is(e, d.ErrRate) {
		t.Fatal(e)
	}
	for _, n := range []int{0, 51, -1} {
		if _, e := s.List(t.Context(), "a", "", n); !errors.Is(e, d.ErrInvalid) {
			t.Fatal(e)
		}
	}
	if r.calls != 3 {
		t.Fatal(r.calls)
	}
}
