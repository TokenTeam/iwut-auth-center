package usecase

import (
	"context"
	"errors"
	"fmt"

	"iwut-auth-center/internal/developer/domain"
	"iwut-auth-center/internal/developer/port"
)

const MaxBatchSize = 100

var (
	ErrInvalidDeveloperStatusQuery = errors.New("invalid developer status query")
	ErrDeveloperStatusNotFound     = errors.New("developer status not found")
)

type DeveloperStatusEntry struct {
	AccountStatus   domain.AccountStatus
	AuthID          domain.AuthID
	DeveloperStatus domain.DeveloperStatus
}

type BatchGetDeveloperStatusesHandler struct {
	repository port.PrincipalRepository
}

func NewBatchGetDeveloperStatusesHandler(repository port.PrincipalRepository) *BatchGetDeveloperStatusesHandler {
	return &BatchGetDeveloperStatusesHandler{repository: repository}
}

func (handler *BatchGetDeveloperStatusesHandler) Handle(
	ctx context.Context,
	rawAuthIDs []string,
) ([]DeveloperStatusEntry, error) {
	if handler == nil || handler.repository == nil {
		return nil, fmt.Errorf("%w: repository is unavailable", port.ErrDeveloperStatusUnavailable)
	}
	if len(rawAuthIDs) == 0 || len(rawAuthIDs) > MaxBatchSize {
		return nil, ErrInvalidDeveloperStatusQuery
	}

	authIDs := make([]domain.AuthID, 0, len(rawAuthIDs))
	seen := make(map[domain.AuthID]struct{}, len(rawAuthIDs))
	for _, raw := range rawAuthIDs {
		authID, err := domain.NewAuthID(raw)
		if err != nil {
			return nil, ErrInvalidDeveloperStatusQuery
		}
		if _, duplicate := seen[authID]; duplicate {
			return nil, ErrInvalidDeveloperStatusQuery
		}
		seen[authID] = struct{}{}
		authIDs = append(authIDs, authID)
	}

	principals, err := handler.repository.BatchGet(ctx, authIDs)
	if err != nil {
		return nil, err
	}
	byID := make(map[domain.AuthID]domain.Principal, len(principals))
	for _, principal := range principals {
		if _, duplicate := byID[principal.AuthID()]; duplicate {
			return nil, fmt.Errorf("%w: duplicate principal", port.ErrDeveloperStatusUnavailable)
		}
		byID[principal.AuthID()] = principal
	}

	entries := make([]DeveloperStatusEntry, 0, len(authIDs))
	for _, authID := range authIDs {
		principal, found := byID[authID]
		if !found || principal.PrincipalType() != domain.PrincipalTypeUser || principal.AccountStatus() != domain.AccountClosed && !principal.DeveloperStatus().IsValid() {
			return nil, ErrDeveloperStatusNotFound
		}
		entries = append(entries, DeveloperStatusEntry{AuthID: authID, DeveloperStatus: principal.DeveloperStatus(), AccountStatus: principal.AccountStatus()})
	}
	if len(byID) != len(authIDs) {
		return nil, fmt.Errorf("%w: repository returned unrequested principal", port.ErrDeveloperStatusUnavailable)
	}
	return entries, nil
}
