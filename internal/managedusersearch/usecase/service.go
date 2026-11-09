package usecase

import (
	"context"
	"iwut-auth-center/internal/managedusersearch/domain"
	"iwut-auth-center/internal/managedusersearch/port"
	"time"
)

type Service struct {
	repository port.Repository
	limiter    port.Limiter
}

func New(repository port.Repository, limiter port.Limiter) *Service {
	return &Service{repository, limiter}
}
func (s *Service) Search(ctx context.Context, actor string, query domain.Query) (domain.Result, error) {
	if !domain.ValidID(actor) {
		return domain.Result{}, domain.ErrIdentity
	}
	if !s.limiter.AllowBegin(actor, time.Now()) {
		return domain.Result{}, domain.ErrRate
	}
	return s.repository.Search(ctx, actor, query)
}
