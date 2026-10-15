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
	repository   port.Repository
	catalog      port.Catalog
	academicYear port.AcademicYearProvider
	now          func() time.Time
}

func NewProfileService(repository port.Repository, catalog port.Catalog, academicYear port.AcademicYearProvider) *Service {
	return &Service{repository: repository, catalog: catalog, academicYear: academicYear, now: time.Now}
}
func (s *Service) read(ctx context.Context, id string) (domain.Principal, error) {
	p, e := s.repository.Read(ctx, id)
	if e != nil {
		return p, e
	}
	return p, domain.CheckPrincipal(p)
}
func (s *Service) GetOwnProfile(ctx context.Context, id string) (domain.Snapshot, error) {
	var snapshot domain.Snapshot
	err := s.repository.Transaction(ctx, func(tx context.Context) error {
		principal, err := s.read(tx, id)
		if err != nil {
			return err
		}
		domain.Sort(principal.Profile.Entries)
		snapshot = principal.Profile
		return nil
	})
	return snapshot, err
}
func (s *Service) GetProfileEditingSchema(ctx context.Context, id string) ([]domain.Definition, *int32, error) {
	var definitions []domain.Definition
	var academicYear *int32
	err := s.repository.Transaction(ctx, func(tx context.Context) error {
		var err error
		definitions, academicYear, err = s.profileEditingSchema(tx, id)
		return err
	})
	return definitions, academicYear, err
}

func (s *Service) profileEditingSchema(ctx context.Context, id string) ([]domain.Definition, *int32, error) {
	if _, e := s.read(ctx, id); e != nil {
		return nil, nil, e
	}
	defs, err := s.definitions(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, definition := range defs {
		if definition.ValueType == domain.AcademicGrade {
			year, err := s.currentAcademicYear(ctx, s.now())
			if err != nil {
				return nil, nil, err
			}
			return defs, &year, nil
		}
	}
	return defs, nil, nil
}

func (s *Service) currentAcademicYear(ctx context.Context, now time.Time) (int32, error) {
	if s.academicYear == nil {
		return 0, domain.ErrAcademicYear
	}
	year, err := s.academicYear.CurrentAcademicYear(ctx, now)
	if err != nil {
		return 0, domain.ErrAcademicYear
	}
	return year, nil
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
	if err := domain.ValidateCommand(c); err != nil {
		return domain.Result{}, err
	}
	var result domain.Result
	err := s.repository.Transaction(ctx, func(tx context.Context) error {
		var err error
		result, err = s.editOwnProfile(tx, id, c)
		return err
	})
	return result, err
}

func (s *Service) editOwnProfile(ctx context.Context, id string, c domain.Command) (domain.Result, error) {
	p, e := s.read(ctx, id)
	if e != nil {
		return domain.Result{}, e
	}
	if p.Profile.Revision != c.ExpectedRevision {
		return domain.Result{}, domain.ErrConflict
	}
	operationTime := s.now().UTC().Truncate(time.Millisecond)
	if len(c.Set) > 0 {
		defs, e := s.definitions(ctx)
		if e != nil {
			return domain.Result{}, e
		}
		definitionsByKey := map[string]domain.Definition{}
		for _, d := range defs {
			definitionsByKey[d.Key] = d
		}
		assignments := append([]domain.Entry{}, c.Set...)
		domain.Sort(assignments)
		currentValues := map[string]domain.Value{}
		for _, entry := range p.Profile.Entries {
			currentValues[entry.Key] = entry.Value
		}
		for assignmentIndex, a := range assignments {
			d, ok := definitionsByKey[a.Key]
			if !ok {
				return domain.Result{}, domain.ErrNotDefined
			}
			if e := domain.ValidateAssignment(a, d, operationTime); e != nil {
				return domain.Result{}, e
			}
			a.Value = domain.Canonicalize(a.Value)
			if a.Value.Academic != nil {
				grade := *a.Value.Academic
				a.Value.Academic = &grade
			}
			if a.Value.Type == domain.AcademicGrade {
				year, err := s.currentAcademicYear(ctx, operationTime)
				if err != nil {
					return domain.Result{}, err
				}
				if a.Value.Academic.AcademicYear != year {
					return domain.Result{}, domain.ErrAcademicYearConflict
				}
				stored, exists := currentValues[a.Key]
				if exists && stored.Type == domain.AcademicGrade && stored.Academic != nil && stored.Academic.Stage == a.Value.Academic.Stage && stored.Academic.Year == a.Value.Academic.Year && stored.Academic.FinalYear == a.Value.Academic.FinalYear && stored.Academic.AcademicYear == a.Value.Academic.AcademicYear {
					a.Value = stored
				} else {
					confirmed := operationTime
					a.Value.Academic.ConfirmedAt = &confirmed
				}
			}
			assignments[assignmentIndex] = a
		}
		c.Set = assignments
	}
	values := map[string]domain.Value{}
	for _, a := range p.Profile.Entries {
		values[a.Key] = a.Value
	}
	for _, key := range c.Remove {
		delete(values, key)
	}
	for _, a := range c.Set {
		values[a.Key] = domain.Canonicalize(a.Value)
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
			if a.Key != p.Profile.Entries[i].Key || !a.Value.Equal(p.Profile.Entries[i].Value) {
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
	candidate.UpdatedAt = operationTime
	if e := s.repository.Commit(ctx, id, c.ExpectedRevision, candidate); e != nil {
		return domain.Result{}, e
	}
	return domain.Result{Changed: true, Profile: candidate}, nil
}
