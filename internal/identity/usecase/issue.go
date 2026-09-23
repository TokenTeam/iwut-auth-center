package usecase

import (
	"context"
	"iwut-auth-center/internal/identity/domain"
	"iwut-auth-center/internal/identity/port"
	"time"
)

type Service struct {
	repository port.Repository
	signer     port.Signer
	tokens     port.Tokens
	ttl        time.Duration
	now        func() time.Time
}

func New(repository port.Repository, signer port.Signer, tokens port.Tokens, ttl time.Duration) (*Service, error) {
	if repository == nil || signer == nil || tokens == nil || ttl < time.Second || ttl > 300*time.Second || ttl%time.Second != 0 {
		return nil, domain.ErrUnavailable
	}
	return &Service{repository: repository, signer: signer, tokens: tokens, ttl: ttl, now: time.Now}, nil
}
func (s *Service) Issue(ctx context.Context, token, audience string, allowed []string) (domain.Issued, error) {
	if !domain.KnownAudience(audience) {
		return domain.Issued{}, domain.ErrInvalidRequest
	}
	authorized := false
	for _, a := range allowed {
		if a == audience {
			authorized = true
		}
	}
	if !authorized {
		return domain.Issued{}, domain.ErrForbidden
	}
	digest, err := s.tokens.TokenDigest(token)
	if err != nil {
		return domain.Issued{}, domain.ErrSessionInvalid
	}
	jti, err := s.tokens.NewID()
	if err != nil {
		return domain.Issued{}, domain.ErrUnavailable
	}
	var candidate domain.Issued
	err = s.repository.WithSession(ctx, digest, func(snapshot domain.Snapshot, now time.Time) error {
		candidate = domain.Issued{}
		claims, err := domain.Project(snapshot, audience, jti, now, s.ttl)
		if err != nil {
			return err
		}
		value, err := s.signer.Sign(ctx, claims)
		if err != nil {
			return domain.ErrUnavailable
		}
		if value == "" || len(value) > 16*1024 {
			return domain.ErrUnavailable
		}
		if s.now().Unix() >= claims.ExpiresAt {
			return domain.ErrSessionInvalid
		}
		candidate = domain.Issued{JWS: value, ExpiresAt: claims.ExpiresAt}
		return nil
	})
	if ctx.Err() != nil {
		return domain.Issued{}, ctx.Err()
	}
	if err != nil {
		return domain.Issued{}, err
	}
	if candidate.JWS == "" {
		return domain.Issued{}, domain.ErrUnavailable
	}
	if s.now().Unix() >= candidate.ExpiresAt {
		return domain.Issued{}, domain.ErrSessionInvalid
	}
	return candidate, nil
}
