package usecase

import (
	"context"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
	"time"
)

type ReauthService struct {
	repository p.ReauthRepository
	engine     p.Engine
	quota      p.Quota
	clock      func() time.Time
}

func NewReauth(r p.ReauthRepository, e p.Engine, q p.Quota) (*ReauthService, error) {
	if r == nil || e == nil || q == nil {
		return nil, d.ErrUnavailable
	}
	return &ReauthService{r, e, q, time.Now}, nil
}
func (s *ReauthService) SetClock(clock func() time.Time) {
	if clock != nil {
		s.clock = clock
	}
}
func (s *ReauthService) VerifyPassword(ctx context.Context, in p.ReauthRequest) (int64, error) {
	now := s.clock().UTC().Truncate(time.Millisecond)
	if err := s.quota.General(ctx, in.Source, "", now); err != nil {
		return 0, err
	}
	if _, err := s.engine.Normalize(in.Password); err != nil {
		return 0, err
	}
	record, err := s.repository.ReadReauth(ctx, in, now)
	if err != nil {
		return 0, err
	}
	if err = s.quota.OwnerRequest(ctx, record.AuthID, now); err != nil {
		return 0, err
	}
	if err = s.quota.Work(ctx, in.Source, record.AuthID, 1, now); err != nil {
		return 0, err
	}
	matched, err := s.engine.Verify(ctx, in.Password, record.Material)
	if err != nil {
		return 0, err
	}
	if !matched {
		return 0, d.ErrAuthentication
	}
	return record.Revision, nil
}
