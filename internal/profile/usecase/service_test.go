package usecase

import (
	"context"
	"errors"
	"iwut-auth-center/internal/profile/domain"
	"math"
	"testing"
	"time"
)

type testRepo struct {
	p                        domain.Principal
	reads, commits, confirms int
	confirmErr               error
}

func (r *testRepo) Read(context.Context, string) (domain.Principal, error) {
	r.reads++
	p := r.p
	p.Profile.Entries = append([]domain.Entry{}, p.Profile.Entries...)
	return p, nil
}
func (r *testRepo) Confirm(context.Context, string, int64) (domain.Snapshot, error) {
	r.confirms++
	return r.p.Profile, r.confirmErr
}
func (r *testRepo) Commit(_ context.Context, _ string, _ int64, s domain.Snapshot) error {
	r.commits++
	r.p.Profile = s
	return nil
}

type testCatalog struct {
	defs  []domain.Definition
	err   error
	calls int
}

func (c *testCatalog) Snapshot(context.Context) ([]domain.Definition, error) {
	c.calls++
	return c.defs, c.err
}
func fixture() (*Service, *testRepo, *testCatalog) {
	r := &testRepo{p: domain.Principal{AuthID: "u", Type: "USER", AccountStatus: "ACTIVE", Profile: domain.Snapshot{Entries: []domain.Entry{}, Revision: 1, UpdatedAt: time.Unix(100, 0)}}}
	c := &testCatalog{defs: []domain.Definition{{Key: "flag", Label: "Flag", Description: "test", ValueType: domain.Boolean, Constraints: &domain.Constraints{}}}}
	return NewProfileService(r, c), r, c
}
func TestEditNoopConflictAndIsolation(t *testing.T) {
	s, r, _ := fixture()
	ctx := context.Background()
	cmd := domain.Command{ExpectedRevision: 1, Set: []domain.Entry{{Key: "flag", Value: domain.Value{Type: domain.Boolean}}}}
	result, e := s.EditOwnProfile(ctx, "u", cmd)
	if e != nil || !result.Changed || result.Profile.Revision != 2 {
		t.Fatalf("edit: %+v %v", result, e)
	}
	if r.commits != 1 {
		t.Fatal("missing commit")
	}
	if _, e = s.EditOwnProfile(ctx, "u", cmd); !errors.Is(e, domain.ErrConflict) {
		t.Fatal("stale identical command succeeded")
	}
	cmd.ExpectedRevision = 2
	result, e = s.EditOwnProfile(ctx, "u", cmd)
	if e != nil || result.Changed || r.confirms != 1 || r.commits != 1 {
		t.Fatal("no-op mutated")
	}
	r.confirmErr = domain.ErrDisabled
	if _, e = s.EditOwnProfile(ctx, "u", cmd); !errors.Is(e, domain.ErrDisabled) {
		t.Fatal("no-op skipped final authority")
	}
}
func TestValidationOrderingAndPureDelete(t *testing.T) {
	s, r, c := fixture()
	ctx := context.Background()
	if _, e := s.EditOwnProfile(ctx, "u", domain.Command{}); e != domain.ErrInvalidRevision || r.reads != 0 {
		t.Fatal("shape read repository")
	}
	r.p.AccountStatus = "DISABLED"
	if _, e := s.EditOwnProfile(ctx, "u", domain.Command{ExpectedRevision: 9, Remove: []string{"x"}}); e != domain.ErrDisabled {
		t.Fatal("status must precede revision")
	}
	r.p.AccountStatus = "ACTIVE"
	c.err = domain.ErrCatalog
	r.p.Profile.Entries = []domain.Entry{{Key: "legacy", Value: domain.Value{Type: domain.Integer, Integer: 7}}}
	if _, e := s.GetOwnProfile(ctx, "u"); e != nil {
		t.Fatal("get depends on catalog")
	}
	result, e := s.EditOwnProfile(ctx, "u", domain.Command{ExpectedRevision: 1, Remove: []string{"legacy"}})
	if e != nil || !result.Changed || c.calls != 0 {
		t.Fatal("pure delete depends on catalog")
	}
	_, e = s.EditOwnProfile(ctx, "u", domain.Command{ExpectedRevision: 2, Set: []domain.Entry{{Key: "flag", Value: domain.Value{Type: domain.Boolean}}}, Remove: []string{"missing"}})
	if e != domain.ErrCatalog || r.commits != 1 {
		t.Fatal("mixed command partly committed")
	}
}
func TestRevisionExhaustionAndUntouchedHistory(t *testing.T) {
	s, r, _ := fixture()
	r.p.Profile.Revision = math.MaxInt64
	r.p.Profile.Entries = []domain.Entry{{Key: "legacy", Value: domain.Value{Type: domain.Integer, Integer: 9}}}
	ctx := context.Background()
	result, e := s.EditOwnProfile(ctx, "u", domain.Command{ExpectedRevision: math.MaxInt64, Remove: []string{"absent"}})
	if e != nil || result.Changed {
		t.Fatal("max revision no-op failed")
	}
	_, e = s.EditOwnProfile(ctx, "u", domain.Command{ExpectedRevision: math.MaxInt64, Remove: []string{"legacy"}})
	if e != domain.ErrExhausted || r.commits != 0 {
		t.Fatal("revision overflow")
	}
	r.p.Profile.Revision = 1
	result, e = s.EditOwnProfile(ctx, "u", domain.Command{ExpectedRevision: 1, Set: []domain.Entry{{Key: "flag", Value: domain.Value{Type: domain.Boolean, Boolean: true}}}})
	if e != nil || len(result.Profile.Entries) != 2 || result.Profile.Entries[1].Key != "legacy" {
		t.Fatal("untouched history removed")
	}
}
