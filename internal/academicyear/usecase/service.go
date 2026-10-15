package usecase

import (
	"context"
	"strings"
	"time"

	d "iwut-auth-center/internal/academicyear/domain"
	"iwut-auth-center/internal/academicyear/port"
)

type Service struct {
	repository port.Repository
	limiter    port.Limiter
	now        func() time.Time
}

func New(repository port.Repository, limiter port.Limiter) *Service {
	return &Service{repository: repository, limiter: limiter, now: time.Now}
}

func (service *Service) gate(actor string, write bool) error {
	if !d.ValidAuthID(actor) {
		return d.ErrInvalid
	}
	if service.repository == nil || service.limiter == nil {
		return d.ErrUnavailable
	}
	if write {
		if !service.limiter.AllowComplete(actor, service.now()) {
			return d.ErrRate
		}
	} else if !service.limiter.AllowBegin(actor, service.now()) {
		return d.ErrRate
	}
	return nil
}

func (service *Service) Get(ctx context.Context, actor string) (d.Schedule, error) {
	if err := service.gate(actor, false); err != nil {
		return d.Schedule{}, err
	}
	return service.repository.Get(ctx, actor)
}

func (service *Service) Update(ctx context.Context, command d.Command) (d.Schedule, error) {
	command.Reason = strings.TrimSpace(command.Reason)
	if !command.Valid() {
		return d.Schedule{}, d.ErrInvalid
	}
	if err := service.gate(command.ActorAuthID, true); err != nil {
		return d.Schedule{}, err
	}
	return service.repository.Update(ctx, command)
}
