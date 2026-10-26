package usecase

import (
	"context"
	d "iwut-auth-center/internal/scopemanagement/domain"
	"iwut-auth-center/internal/scopemanagement/port"
	"time"
)

type Service struct {
	repository port.Repository
	limiter    port.Limiter
	now        func() time.Time
}

func New(repository port.Repository, limiter port.Limiter) *Service {
	return &Service{repository: repository, limiter: limiter, now: time.Now}
}
func (s *Service) gate(actor string, write bool) error {
	if !d.ValidAuthID(actor) {
		return d.ErrInvalid
	}
	if s.repository == nil || s.limiter == nil {
		return d.ErrUnavailable
	}
	if write {
		if !s.limiter.AllowComplete(actor, s.now()) {
			return d.ErrRate
		}
	} else if !s.limiter.AllowBegin(actor, s.now()) {
		return d.ErrRate
	}
	return nil
}
func (s *Service) Get(ctx context.Context, actor string) (d.Snapshot, error) {
	if err := s.gate(actor, false); err != nil {
		return d.Snapshot{}, err
	}
	return s.repository.Get(ctx, actor)
}
func (s *Service) Change(ctx context.Context, c d.Command) (d.Operation, error) {
	c = c.Normalize()
	if !c.Valid() {
		return d.Operation{}, d.ErrInvalid
	}
	if err := s.gate(c.ActorAuthID, true); err != nil {
		return d.Operation{}, err
	}
	return s.repository.Change(ctx, c)
}
func (s *Service) Operation(ctx context.Context, actor, id string) (d.Operation, error) {
	if !d.ValidOperationID(id) {
		return d.Operation{}, d.ErrInvalid
	}
	if err := s.gate(actor, false); err != nil {
		return d.Operation{}, err
	}
	return s.repository.Operation(ctx, actor, id)
}
