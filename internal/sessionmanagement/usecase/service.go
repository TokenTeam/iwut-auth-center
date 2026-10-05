package usecase

import (
	"context"
	d "iwut-auth-center/internal/sessionmanagement/domain"
	"iwut-auth-center/internal/sessionmanagement/port"
	"time"
)

type Service struct {
	repo    port.Repository
	ids     port.IDGenerator
	limiter port.AccountLimiter
	clock   func() time.Time
}

func New(repo port.Repository, ids port.IDGenerator, limiter port.AccountLimiter) (*Service, error) {
	if repo == nil || ids == nil || limiter == nil {
		return nil, d.ErrUnavailable
	}
	return &Service{repo, ids, limiter, time.Now}, nil
}
func (s *Service) SetClock(clock func() time.Time) {
	if clock != nil {
		s.clock = clock
	}
}
func (s *Service) admit(ctx context.Context, digest []byte, now time.Time) error {
	if len(digest) != 32 {
		return d.ErrSessionInvalid
	}
	id, e := s.repo.Authenticate(ctx, digest, now)
	if e != nil {
		return e
	}
	if !s.limiter.AllowAccount(id, now) {
		return d.ErrRateLimited
	}
	return nil
}
func (s *Service) List(ctx context.Context, digest []byte, pageSize int, cursor string) (d.Page, error) {
	if e := d.ValidateList(pageSize, cursor); e != nil {
		return d.Page{}, e
	}
	now := s.clock().UTC().Truncate(time.Millisecond)
	if e := s.admit(ctx, digest, now); e != nil {
		return d.Page{}, e
	}
	return s.repo.List(ctx, digest, pageSize, cursor, now)
}
func (s *Service) Revoke(ctx context.Context, digest []byte, ids []string) error {
	if e := d.ValidateTargets(ids); e != nil {
		return e
	}
	now := s.clock().UTC().Truncate(time.Millisecond)
	if e := s.admit(ctx, digest, now); e != nil {
		return e
	}
	event, e := s.ids.NewID()
	if e != nil || !d.ValidID(event) {
		return d.ErrUnavailable
	}
	return s.repo.Revoke(ctx, digest, append([]string(nil), ids...), event, now)
}
