package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"
	d "iwut-auth-center/internal/applicationuserstorage/domain"
	"iwut-auth-center/internal/applicationuserstorage/port"
)

type Service struct {
	repository port.Repository
	now        func() time.Time
}

func New(repository port.Repository) *Service {
	return &Service{repository: repository, now: time.Now}
}

func (s *Service) Clear(ctx context.Context, authID, applicationID string) (bool, error) {
	if s == nil || s.repository == nil || authID == "" || applicationID == "" {
		return false, d.ErrInvalid
	}
	id, err := uuid.Parse(applicationID)
	if err != nil || id.String() != applicationID {
		return false, d.ErrInvalid
	}
	return s.repository.Clear(ctx, authID, applicationID, s.now().UTC())
}
