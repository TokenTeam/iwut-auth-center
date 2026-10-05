package usecase

import (
	"context"
	d "iwut-auth-center/internal/developer/domain"
	"iwut-auth-center/internal/developer/port"
	"strings"
	"time"
)

type Management struct {
	repo    port.ManagementRepository
	limiter port.ManagementLimiter
}

func NewManagement(r port.ManagementRepository, l port.ManagementLimiter) *Management {
	return &Management{r, l}
}
func (s *Management) Manage(ctx context.Context, c d.ManageDeveloperCommand) (d.ManagedDeveloperState, error) {
	c.Reason = strings.TrimSpace(c.Reason)
	if !c.Valid() {
		return d.ManagedDeveloperState{}, d.ErrManagementInvalid
	}
	if s.repo == nil || s.limiter == nil {
		return d.ManagedDeveloperState{}, d.ErrManagementUnavailable
	}
	if !s.limiter.AllowComplete(c.ActorAuthID, time.Now()) {
		return d.ManagedDeveloperState{}, d.ErrManagementRate
	}
	return s.repo.ManageDeveloperStatus(ctx, c)
}
func (s *Management) Get(ctx context.Context, actor, subject string) (d.ManagedDeveloperState, error) {
	if _, e := d.NewAuthID(actor); e != nil {
		return d.ManagedDeveloperState{}, d.ErrManagementInvalid
	}
	if _, e := d.NewAuthID(subject); e != nil || strings.TrimSpace(subject) != subject {
		return d.ManagedDeveloperState{}, d.ErrManagementInvalid
	}
	if s.repo == nil || s.limiter == nil {
		return d.ManagedDeveloperState{}, d.ErrManagementUnavailable
	}
	if !s.limiter.AllowBegin(actor, time.Now()) {
		return d.ManagedDeveloperState{}, d.ErrManagementRate
	}
	return s.repo.GetManagedDeveloperStatus(ctx, actor, subject)
}
