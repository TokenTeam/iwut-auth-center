package identitysigner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"iwut-auth-center/internal/identity/domain"
	"strings"
)

type Signer struct {
	key         *rsa.PrivateKey
	issuer, kid string
}

func New(issuer, kid string, key *rsa.PrivateKey) (*Signer, error) {
	if issuer == "" || kid == "" || strings.TrimSpace(kid) != kid || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, domain.ErrUnavailable
	}
	// Deep copy prevents a caller changing key material after construction.
	k := *key
	keyDER := x509.MarshalPKCS1PrivateKey(&k)
	cloned, err := x509.ParsePKCS1PrivateKey(keyDER)
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	cloned.Precompute()
	return &Signer{issuer: issuer, kid: kid, key: cloned}, nil
}
func (s *Signer) Sign(ctx context.Context, c domain.Claims) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	header, _ := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}{"RS256", "JWT", s.kid})
	permissions := c.Permissions
	if permissions == nil {
		permissions = []string{}
	}
	payload, err := json.Marshal(struct {
		Iss             string   `json:"iss"`
		Sub             string   `json:"sub"`
		Aud             string   `json:"aud"`
		Iat             int64    `json:"iat"`
		Nbf             int64    `json:"nbf"`
		Exp             int64    `json:"exp"`
		Jti             string   `json:"jti"`
		Permissions     []string `json:"permissions"`
		DeveloperStatus string   `json:"developer_status,omitempty"`
	}{s.issuer, c.AuthID, c.Audience, c.IssuedAt, c.IssuedAt, c.ExpiresAt, c.JTI, permissions, c.DeveloperStatus})
	if err != nil {
		return "", domain.ErrUnavailable
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", domain.ErrUnavailable
	}
	result := input + "." + base64.RawURLEncoding.EncodeToString(sig)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if len(result) > 16*1024 {
		return "", domain.ErrUnavailable
	}
	return result, nil
}
