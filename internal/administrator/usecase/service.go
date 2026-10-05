package usecase

import (
	"context"
	d "iwut-auth-center/internal/administrator/domain"
	"iwut-auth-center/internal/administrator/port"
	"strings"
	"time"
)

type Service struct {
	repo    port.Repository
	limiter port.Limiter
}

func New(r port.Repository, l port.Limiter) *Service { return &Service{r, l} }
func (s *Service) gate(actor string, write bool) error {
	if !d.ValidID(actor) {
		return d.ErrInvalid
	}
	if s.repo == nil || s.limiter == nil {
		return d.ErrUnavailable
	}
	if write {
		if !s.limiter.AllowComplete(actor, time.Now()) {
			return d.ErrRate
		}
	} else if !s.limiter.AllowBegin(actor, time.Now()) {
		return d.ErrRate
	}
	return nil
}
func (s *Service) Manage(ctx context.Context, c d.Command) (d.State, error) {
	c.Reason = strings.TrimSpace(c.Reason)
	if !c.Valid() {
		return d.State{}, d.ErrInvalid
	}
	if e := s.gate(c.ActorAuthID, true); e != nil {
		return d.State{}, e
	}
	return s.repo.Manage(ctx, c)
}
func (s *Service) Get(ctx context.Context, actor, subject string) (d.State, error) {
	if !d.ValidID(subject) {
		return d.State{}, d.ErrInvalid
	}
	if e := s.gate(actor, false); e != nil {
		return d.State{}, e
	}
	return s.repo.Get(ctx, actor, subject)
}
func (s *Service) List(ctx context.Context, actor, after string, size int) (d.Page, error) {
	if size < 1 || size > 50 || (after != "" && !d.ValidID(after)) {
		return d.Page{}, d.ErrInvalid
	}
	if e := s.gate(actor, false); e != nil {
		return d.Page{}, e
	}
	return s.repo.List(ctx, actor, after, size)
}
