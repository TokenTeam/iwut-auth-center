package usecase

import (
	"context"
	"errors"
	d "iwut-auth-center/internal/developerwithdrawal/domain"
	p "iwut-auth-center/internal/developerwithdrawal/port"
	o "iwut-auth-center/internal/ownerexit/domain"
	owner "iwut-auth-center/internal/ownerexit/usecase"
	"time"
)

type Service struct {
	repo        p.Repository
	tokens      p.Tokens
	limiter     p.Limiter
	coordinator *owner.Coordinator
}

func New(r p.Repository, t p.Tokens, l p.Limiter, c *owner.Coordinator) *Service {
	return &Service{r, t, l, c}
}
func (s *Service) admit(ctx context.Context, digest []byte, write bool) error {
	if s == nil || s.repo == nil || s.limiter == nil {
		return d.ErrUnavailable
	}
	id, e := s.repo.Authenticate(ctx, digest, time.Now().UTC())
	if e != nil {
		return e
	}
	if write {
		if !s.limiter.AllowLocator(id, time.Now()) {
			return d.ErrRate
		}
	} else if !s.limiter.AllowBegin(id, time.Now()) {
		return d.ErrRate
	}
	return nil
}
func (s *Service) Prepare(ctx context.Context, digest []byte, request string, revision int64) (d.Result, error) {
	if !o.ValidOperationID(request) || revision < 1 {
		return d.Result{}, d.ErrInvalid
	}
	if e := s.admit(ctx, digest, true); e != nil {
		return d.Result{}, e
	}
	id, e := s.tokens.NewID()
	if e != nil {
		return d.Result{}, d.ErrUnavailable
	}
	op, e := s.repo.Prepare(ctx, digest, request, id, revision, time.Now().UTC())
	if e != nil {
		return d.Result{}, e
	}
	if _, e = s.coordinator.Prepare(ctx, op); e != nil {
		if errors.Is(e, o.ErrConflict) {
			return d.Result{}, d.ErrConflict
		}
		return d.Result{}, d.ErrUnavailable
	}
	return s.repo.Read(ctx, digest, op.OperationID, time.Now().UTC())
}
func (s *Service) Get(ctx context.Context, digest []byte, id string) (d.Result, error) {
	if !o.ValidOperationID(id) {
		return d.Result{}, d.ErrInvalid
	}
	if e := s.admit(ctx, digest, false); e != nil {
		return d.Result{}, e
	}
	return s.repo.Read(ctx, digest, id, time.Now().UTC())
}
func (s *Service) Confirm(ctx context.Context, digest []byte, id, confirmation string) (d.Result, error) {
	if !o.ValidOperationID(id) || confirmation != "WITHDRAW_DEVELOPER" {
		return d.Result{}, d.ErrInvalid
	}
	if e := s.admit(ctx, digest, true); e != nil {
		return d.Result{}, e
	}
	return s.repo.Confirm(ctx, digest, id, time.Now().UTC())
}
func (s *Service) Cancel(ctx context.Context, digest []byte, id string) (d.Result, error) {
	if !o.ValidOperationID(id) {
		return d.Result{}, d.ErrInvalid
	}
	if e := s.admit(ctx, digest, true); e != nil {
		return d.Result{}, e
	}
	return s.repo.Cancel(ctx, digest, id, time.Now().UTC())
}
