package usecase

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	d "iwut-auth-center/internal/applicationclosure/domain"
	p "iwut-auth-center/internal/applicationclosure/port"
)

type Service struct {
	repository p.Repository
	clock      func() time.Time
	newID      func() (uuid.UUID, error)
}

func New(repository p.Repository) *Service {
	return &Service{repository: repository, clock: time.Now, newID: uuid.NewV7}
}

func canonicalID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && strings.ToLower(id.String()) == value
}

func (s *Service) Apply(ctx context.Context, applicationID, closureID string, closingStartedAt time.Time, caller string) (d.Tombstone, error) {
	if s == nil || s.repository == nil || !canonicalID(applicationID) || !canonicalID(closureID) || closingStartedAt.IsZero() || closingStartedAt.Location() == nil || caller == "" {
		return d.Tombstone{}, d.ErrInvalid
	}
	receipt, err := s.newID()
	if err != nil {
		return d.Tombstone{}, d.ErrUnavailable
	}
	now := s.clock().UTC().Truncate(time.Millisecond)
	return s.repository.Apply(ctx, applicationID, closureID, closingStartedAt.UTC().Truncate(time.Millisecond), receipt.String(), caller, now)
}

func (s *Service) Get(ctx context.Context, applicationID, closureID string) (d.Tombstone, error) {
	if s == nil || s.repository == nil || !canonicalID(applicationID) || !canonicalID(closureID) {
		return d.Tombstone{}, d.ErrInvalid
	}
	return s.repository.Get(ctx, applicationID, closureID)
}
