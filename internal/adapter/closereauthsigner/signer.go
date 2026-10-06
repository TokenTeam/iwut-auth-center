package closereauthsigner

import (
	"context"
	"crypto/rsa"
	"strings"

	"iwut-auth-center/internal/adapter/oauthcrypto"
	d "iwut-auth-center/internal/applicationclosereauth/domain"
)

type Signer struct{ key oauthcrypto.Key }

func New(kid string, key *rsa.PrivateKey) (*Signer, error) {
	if kid == "" || strings.TrimSpace(kid) != kid || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, d.ErrUnavailable
	}
	return &Signer{key: oauthcrypto.Key{ID: kid, Private: key}}, nil
}

func (s *Signer) Sign(ctx context.Context, c d.Claims) (string, error) {
	if ctx.Err() != nil {
		return "", d.ErrUnavailable
	}
	proof, err := oauthcrypto.Sign(s.key, "iwut-app-close-reauth+jwt", map[string]any{
		"iss": c.Issuer, "aud": c.Audience, "sub": c.Subject,
		"token_type": c.TokenType, "purpose": c.Purpose, "application_id": c.ApplicationID,
		"jti": c.JTI, "auth_time": c.AuthTime.Unix(), "iat": c.IssuedAt.Unix(),
		"nbf": c.NotBefore.Unix(), "exp": c.ExpiresAt.Unix(),
	})
	if err != nil || ctx.Err() != nil || len(proof) > 16*1024 {
		return "", d.ErrUnavailable
	}
	return proof, nil
}
