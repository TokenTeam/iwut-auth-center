package oauthcrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"

	"github.com/google/uuid"
	d "iwut-auth-center/internal/oauth/domain"
)

type Key struct {
	ID      string
	Private *rsa.PrivateKey
}
type Crypto struct {
	OIDC, Delegation Key
	OldOIDC          map[string]*rsa.PublicKey
}

func New(oidc, delegation Key, old map[string]*rsa.PublicKey) (*Crypto, error) {
	if !validKey(oidc) || !validKey(delegation) || oidc.ID == delegation.ID || oidc.Private.N.Cmp(delegation.Private.N) == 0 {
		return nil, d.ErrUnavailable
	}
	copied := map[string]*rsa.PublicKey{}
	for id, k := range old {
		if id == "" || id == oidc.ID || k == nil || k.N.BitLen() < 2048 || k.N.Cmp(delegation.Private.N) == 0 {
			return nil, d.ErrUnavailable
		}
		b := x509.MarshalPKCS1PublicKey(k)
		v, _ := x509.ParsePKCS1PublicKey(b)
		copied[id] = v
	}
	a, _ := x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(oidc.Private))
	b, _ := x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(delegation.Private))
	return &Crypto{OIDC: Key{oidc.ID, a}, Delegation: Key{delegation.ID, b}, OldOIDC: copied}, nil
}
func validKey(k Key) bool {
	return k.ID != "" && len(k.ID) <= 128 && strings.TrimSpace(k.ID) == k.ID && k.Private != nil && k.Private.N.BitLen() >= 2048 && k.Private.Validate() == nil
}
func ParseKey(data []byte) (*rsa.PrivateKey, error) {
	b, rest := pem.Decode(data)
	if b == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, d.ErrUnavailable
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	v, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, d.ErrUnavailable
	}
	k, ok := v.(*rsa.PrivateKey)
	if !ok {
		return nil, d.ErrUnavailable
	}
	return k, nil
}
func (*Crypto) Random() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (*Crypto) ID() string { return uuid.NewString() }
func (*Crypto) Digest(purpose, raw string) string {
	v := sha256.Sum256([]byte("iwut-oauth-v1\x00" + purpose + "\x00" + raw))
	return base64.RawURLEncoding.EncodeToString(v[:])
}
func (*Crypto) ValidOpaque(raw string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == raw
}
func (c *Crypto) ValidChallenge(raw string) bool { return c.ValidOpaque(raw) }
func (*Crypto) VerifyPKCE(challenge, verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, r := range verifier {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r)) {
			return false
		}
	}
	hash := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(base64.RawURLEncoding.EncodeToString(hash[:]))) == 1
}
func Sign(k Key, typ string, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": typ, "kid": k.ID})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", d.ErrUnavailable
	}
	raw := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(raw))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.Private, crypto.SHA256, hash[:])
	if err != nil {
		return "", d.ErrUnavailable
	}
	out := raw + "." + base64.RawURLEncoding.EncodeToString(sig)
	if len(out) > 8192 {
		return "", d.ErrUnavailable
	}
	return out, nil
}
func (c *Crypto) SignID(v map[string]any) (string, error) { return Sign(c.OIDC, "JWT", v) }
func (c *Crypto) SignDelegation(v map[string]any) (string, error) {
	return Sign(c.Delegation, "iwut-delegation+jwt", v)
}
func (*Crypto) AccessHash(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(h[:16])
}
func (c *Crypto) JWKS() any {
	keys := []map[string]string{jwk(c.OIDC.ID, &c.OIDC.Private.PublicKey)}
	for id, k := range c.OldOIDC {
		keys = append(keys, jwk(id, k))
	}
	return map[string]any{"keys": keys}
}
func jwk(id string, k *rsa.PublicKey) map[string]string {
	return map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": id, "n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
}
