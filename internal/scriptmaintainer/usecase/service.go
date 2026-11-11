package usecase

import (
	"context"
	"strings"
	"time"

	"iwut-auth-center/internal/scriptmaintainer/domain"
	"iwut-auth-center/internal/scriptmaintainer/port"
)

type Service struct {
	repository port.Repository
	limiter    port.Limiter
}

func New(repository port.Repository, limiter port.Limiter) *Service {
	return &Service{repository: repository, limiter: limiter}
}

func (s *Service) Get(ctx context.Context, actor, subject string) (domain.State, error) {
	if !domain.ValidID(actor) || !domain.ValidID(subject) {
		return domain.State{}, domain.ErrInvalid
	}
	if !s.limiter.AllowBegin(actor, time.Now()) {
		return domain.State{}, domain.ErrRate
	}
	return s.repository.Get(ctx, actor, subject)
}

func (s *Service) Manage(ctx context.Context, command domain.Command) (domain.State, error) {
	command.Reason = strings.TrimSpace(command.Reason)
	if !command.Valid() {
		return domain.State{}, domain.ErrInvalid
	}
	if !s.limiter.AllowComplete(command.ActorAuthID, time.Now()) {
		return domain.State{}, domain.ErrRate
	}
	return s.repository.Manage(ctx, command)
}

func (s *Service) GetOwn(ctx context.Context, actor string) (domain.State, error) {
	if !domain.ValidID(actor) {
		return domain.State{}, domain.ErrIdentity
	}
	if !s.limiter.AllowBegin(actor, time.Now()) {
		return domain.State{}, domain.ErrRate
	}
	return s.repository.GetOwn(ctx, actor)
}
