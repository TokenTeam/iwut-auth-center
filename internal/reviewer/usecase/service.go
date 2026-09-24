package usecase

import (
	"context"
	"iwut-auth-center/internal/reviewer/domain"
	"iwut-auth-center/internal/reviewer/port"
	"strings"
)

type Service struct{ repo port.Repository }

func New(repo port.Repository) *Service { return &Service{repo} }
func (s *Service) Manage(ctx context.Context, c domain.Command) (domain.State, error) {
	c.Reason = strings.TrimSpace(c.Reason)
	if !c.Valid() {
		return domain.State{}, domain.ErrInvalid
	}
	return s.repo.Manage(ctx, c)
}
func (s *Service) Get(ctx context.Context, actor, subject string) (domain.State, error) {
	if !domain.ValidID(actor) || !domain.ValidID(subject) {
		return domain.State{}, domain.ErrInvalid
	}
	return s.repo.Get(ctx, actor, subject)
}
func (s *Service) Bootstrap(ctx context.Context, id string) (bool, error) {
	if !domain.ValidID(id) {
		return false, domain.ErrInvalid
	}
	return s.repo.Bootstrap(ctx, id)
}
