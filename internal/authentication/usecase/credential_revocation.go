package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"
	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
)

type CredentialRevocation struct {
	repository port.CredentialRevocationRepository
}

func NewCredentialRevocation(repository port.CredentialRevocationRepository) (*CredentialRevocation, error) {
	if repository == nil {
		return nil, port.ErrUnavailable
	}
	return &CredentialRevocation{repository: repository}, nil
}

func (u *CredentialRevocation) Revoke(ctx context.Context, caller domain.Session, credentialID string) error {
	if caller.AuthID == "" || caller.SessionID == "" || len(caller.TokenDigest) != 32 {
		return port.ErrSessionInvalid
	}
	id, err := uuid.Parse(credentialID)
	if err != nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 || id.String() != credentialID {
		return port.ErrInvalidInput
	}
	return u.repository.RevokeOwnCredential(ctx, caller, credentialID, time.Now().UTC().Truncate(time.Millisecond))
}
