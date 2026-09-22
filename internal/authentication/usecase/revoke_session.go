package usecase

import (
	"context"
	"time"

	"iwut-auth-center/internal/authentication/port"
)

type RevokeCurrentSession struct {
	repository port.SessionRevocationRepository
	tokens     port.SessionTokenDigester
	clock      func() time.Time
}

func NewRevokeCurrentSession(repository port.SessionRevocationRepository, tokens port.SessionTokenDigester) (*RevokeCurrentSession, error) {
	if repository == nil || tokens == nil {
		return nil, port.ErrUnavailable
	}
	return &RevokeCurrentSession{repository: repository, tokens: tokens, clock: time.Now}, nil
}

func (uc *RevokeCurrentSession) Handle(ctx context.Context, token string) error {
	digest, err := uc.tokens.TokenDigest(token)
	if err != nil || len(digest) != 32 {
		return port.ErrInvalidSessionToken
	}
	if err := uc.repository.RevokeCurrentSession(ctx, digest, uc.clock().UTC().Truncate(time.Millisecond)); err != nil {
		// Never expose storage errors, including potentially secret diagnostics.
		return port.ErrUnavailable
	}
	return nil
}
