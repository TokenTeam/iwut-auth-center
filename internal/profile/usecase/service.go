package usecase

import (
	"context"
	"iwut-auth-center/internal/profile/domain"
	"iwut-auth-center/internal/profile/port"
	"math"
	"sort"
	"time"
)

type Service struct {
	repository port.Repository
	catalog    port.Catalog
	now        func() time.Time
}

func NewProfileService(repository port.Repository, catalog port.Catalog) *Service {
	return &Service{repository: repository, catalog: catalog, now: time.Now}
}
func (s *Service) read(ctx context.Context, id string) (domain.Principal, error) {
	p, e := s.repository.Read(ctx, id)
	if e != nil {
		return p, e
	}
	return p, domain.CheckPrincipal(p)
}
func (s *Service) GetOwnProfile(ctx context.Context, id string) (domain.Snapshot, error) {
	p, e := s.read(ctx, id)
	domain.Sort(p.Profile.Entries)
	return p.Profile, e
}
func (s *Service) GetProfileEditingSchema(ctx context.Context, id string) ([]domain.Definition, error) {
	if _, e := s.read(ctx, id); e != nil {
		return nil, e
	}
	return s.definitions(ctx)
}
func (s *Service) definitions(ctx context.Context) ([]domain.Definition, error) {
	if s.catalog == nil {
		return nil, domain.ErrCatalog
	}
	defs, e := s.catalog.Snapshot(ctx)
	if e != nil || domain.ValidateDefinitions(defs) != nil {
		return nil, domain.ErrCatalog
	}
	defs = append([]domain.Definition{}, defs...)
	sort.Slice(defs, func(i, j int) bool { return defs[i].Key < defs[j].Key })
	return defs, nil
}
func (s *Service) EditOwnProfile(ctx context.Context, id string, c domain.Command) (domain.Result, error) {
	if e := domain.ValidateCommand(c); e != nil {
		return domain.Result{}, e
	}
	p, e := s.read(ctx, id)
	if e != nil {
		return domain.Result{}, e
	}
	if p.Profile.Revision != c.ExpectedRevision {
		return domain.Result{}, domain.ErrConflict
	}
	if len(c.Set) > 0 {
		defs, e := s.definitions(ctx)
		if e != nil {
			return domain.Result{}, e
		}
		index := map[string]domain.Definition{}
		for _, d := range defs {
			index[d.Key] = d
		}
		assignments := append([]domain.Entry{}, c.Set...)
		domain.Sort(assignments)
		for _, a := range assignments {
			d, ok := index[a.Key]
			if !ok {
				return domain.Result{}, domain.ErrNotDefined
			}
			if e := domain.ValidateAssignment(a, d); e != nil {
				return domain.Result{}, e
			}
		}
	}
	values := map[string]domain.Value{}
	for _, a := range p.Profile.Entries {
		values[a.Key] = a.Value
	}
	for _, key := range c.Remove {
		delete(values, key)
	}
	for _, a := range c.Set {
		values[a.Key] = a.Value
	}
	candidate := domain.Snapshot{Revision: p.Profile.Revision, UpdatedAt: p.Profile.UpdatedAt, Entries: make([]domain.Entry, 0, len(values))}
	size := 0
	for k, v := range values {
		candidate.Entries = append(candidate.Entries, domain.Entry{Key: k, Value: v})
		size += len(k) + v.Size()
	}
	if len(values) > domain.MaxFields || size > domain.MaxProfileBytes {
		return domain.Result{}, domain.ErrLimit
	}
	domain.Sort(candidate.Entries)
	domain.Sort(p.Profile.Entries)
	same := len(candidate.Entries) == len(p.Profile.Entries)
	if same {
		for i, a := range candidate.Entries {
			if a != p.Profile.Entries[i] {
				same = false
				break
			}
		}
	}
	if same {
		confirmed, e := s.repository.Confirm(ctx, id, c.ExpectedRevision)
		if e != nil {
			return domain.Result{}, e
		}
		domain.Sort(confirmed.Entries)
		return domain.Result{Profile: confirmed}, nil
	}
	if candidate.Revision == math.MaxInt64 {
		return domain.Result{}, domain.ErrExhausted
	}
	candidate.Revision++
	candidate.UpdatedAt = s.now().UTC().Truncate(time.Millisecond)
	if e := s.repository.Commit(ctx, id, c.ExpectedRevision, candidate); e != nil {
		return domain.Result{}, e
	}
	return domain.Result{Changed: true, Profile: candidate}, nil
}
