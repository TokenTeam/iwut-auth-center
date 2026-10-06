package usecase

import (
	"context"
	"strings"
	"time"

	"iwut-auth-center/internal/applicationoperations/domain"
	"iwut-auth-center/internal/applicationoperations/port"
)

type Service struct {
	repository port.Repository
	limiter    port.Limiter
}

func New(repository port.Repository, limiter port.Limiter) *Service {
	return &Service{repository: repository, limiter: limiter}
}

func (s *Service) gate(actor string, write bool) error {
	if !domain.ValidID(actor) {
		return domain.ErrInvalid
	}
	if s.repository == nil || s.limiter == nil {
		return domain.ErrUnavailable
	}
	if write {
		if !s.limiter.AllowComplete(actor, time.Now()) {
			return domain.ErrRate
		}
	} else if !s.limiter.AllowBegin(actor, time.Now()) {
		return domain.ErrRate
	}
	return nil
}

func (s *Service) Manage(ctx context.Context, command domain.Command) (domain.State, error) {
	command.Reason = strings.TrimSpace(command.Reason)
	if !command.Valid() {
		return domain.State{}, domain.ErrInvalid
	}
	if err := s.gate(command.ActorAuthID, true); err != nil {
		return domain.State{}, err
	}
	return s.repository.Manage(ctx, command)
}

func (s *Service) Get(ctx context.Context, actor, subject string) (domain.State, error) {
	if !domain.ValidID(subject) {
		return domain.State{}, domain.ErrInvalid
	}
	if err := s.gate(actor, false); err != nil {
		return domain.State{}, err
	}
	return s.repository.Get(ctx, actor, subject)
}
