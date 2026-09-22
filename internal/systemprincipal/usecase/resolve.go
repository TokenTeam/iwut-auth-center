package usecase

import (
	"context"
	"errors"
	"fmt"

	"iwut-auth-center/internal/systemprincipal/domain"
	"iwut-auth-center/internal/systemprincipal/port"
)

var ErrInvalidSystemPrincipalPurpose = errors.New("invalid system principal purpose")

type ResolveSystemPrincipalHandler struct{ repository port.Repository }

func NewResolveSystemPrincipalHandler(repository port.Repository) *ResolveSystemPrincipalHandler {
	return &ResolveSystemPrincipalHandler{repository: repository}
}

func (handler *ResolveSystemPrincipalHandler) Handle(ctx context.Context, rawPurpose string) (domain.Principal, error) {
	purpose, err := domain.NewPurpose(rawPurpose)
	if err != nil {
		return domain.Principal{}, ErrInvalidSystemPrincipalPurpose
	}
	if handler == nil || handler.repository == nil {
		return domain.Principal{}, fmt.Errorf("%w: repository is unavailable", port.ErrSystemPrincipalUnavailable)
	}
	return handler.repository.Resolve(ctx, purpose)
}
