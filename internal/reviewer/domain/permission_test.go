package domain

import (
	"errors"
	"math"
	"reflect"
	"testing"
)

func TestReviewerChangesPreserveIndependentCapabilities(t *testing.T) {
	s := State{"u", []string{Manager, "z"}, 1}
	next, err := Change(s, Reviewer, "GRANT", 1)
	if err != nil || !reflect.DeepEqual(next.Permissions, []string{Reviewer, Manager, "z"}) || next.Revision != 2 {
		t.Fatal(next, err)
	}
	if s.Has(Reviewer) {
		t.Fatal("mutated original")
	}
	for _, c := range []struct {
		s    State
		a    string
		r    int64
		want error
	}{{next, "GRANT", 2, ErrConflict}, {next, "REVOKE", 1, ErrConflict}, {State{"u", []string{}, math.MaxInt64}, "GRANT", math.MaxInt64, ErrExhausted}} {
		if _, err := Change(c.s, Reviewer, c.a, c.r); !errors.Is(err, c.want) {
			t.Fatal(err)
		}
	}
	revoked, err := Change(next, Reviewer, "REVOKE", 2)
	if err != nil || revoked.Has(Reviewer) || !revoked.Has(Manager) {
		t.Fatal(revoked, err)
	}
}
func TestReviewerCommandRejectsAmbiguousInputs(t *testing.T) {
	c := Command{"a", "s", "GRANT", "a reason", 1}
	if !c.Valid() {
		t.Fatal(c)
	}
	for _, edit := range []func(*Command){func(c *Command) { c.ExpectedRevision = 0 }, func(c *Command) { c.Action = "" }, func(c *Command) { c.Reason = " \n" }, func(c *Command) { c.Reason = string([]byte{255}) }, func(c *Command) { c.SubjectAuthID = " x" }} {
		bad := c
		edit(&bad)
		if bad.Valid() {
			t.Fatal(bad)
		}
	}
}
