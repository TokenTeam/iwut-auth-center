package usecase

import (
	"context"
	"errors"
	d "iwut-auth-center/internal/scopemanagement/domain"
	"strings"
	"testing"
	"time"
)

type repositoryFixture struct {
	last          d.Command
	reads, writes int
}

func (r *repositoryFixture) Get(context.Context, string) (d.Snapshot, error) {
	r.reads++
	return d.Snapshot{}, nil
}
func (r *repositoryFixture) Change(_ context.Context, c d.Command) (d.Operation, error) {
	r.writes++
	r.last = c
	return d.Operation{}, nil
}
func (r *repositoryFixture) Operation(context.Context, string, string) (d.Operation, error) {
	r.reads++
	return d.Operation{}, nil
}

type limitFixture struct{ read, write bool }

func (l limitFixture) AllowBegin(string, time.Time) bool    { return l.read }
func (l limitFixture) AllowComplete(string, time.Time) bool { return l.write }
func TestServiceValidatesNormalizesAndSeparatesQuotas(t *testing.T) {
	r := &repositoryFixture{}
	s := New(r, limitFixture{read: true})
	if _, err := s.Get(t.Context(), "admin"); err != nil {
		t.Fatal(err)
	}
	c := d.Command{ActorAuthID: "admin", OperationID: "90c77db1-e62b-458c-a53b-98bc0bc44424", ExpectedRevision: 1, ExpectedDigest: strings.Repeat("a", 64), Reason: "  reason  ", Changes: []d.Change{{Kind: "SET_ENABLED", Name: "email"}}}
	if _, err := s.Change(t.Context(), c); !errors.Is(err, d.ErrRate) || r.writes != 0 {
		t.Fatal(err)
	}
	s = New(r, limitFixture{read: true, write: true})
	if _, err := s.Change(t.Context(), c); err != nil || r.last.Reason != "reason" {
		t.Fatal(err, r.last)
	}
	c.OperationID = "bad"
	if _, err := s.Change(t.Context(), c); !errors.Is(err, d.ErrInvalid) || r.writes != 1 {
		t.Fatal(err)
	}
	if _, err := s.Operation(t.Context(), "admin", "bad"); !errors.Is(err, d.ErrInvalid) || r.reads != 1 {
		t.Fatal(err)
	}
}
