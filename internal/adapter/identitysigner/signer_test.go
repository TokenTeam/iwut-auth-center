package identitysigner_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"iwut-auth-center/internal/adapter/identitysigner"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/identity/domain"
	"testing"
	"time"
)

func TestProductionSignerRotationThroughActualAuthVerifier(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := func(k *rsa.PrivateKey) []byte {
		d, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: d})
	}
	now := time.Now().Unix()
	claims := domain.Claims{AuthID: "user", Audience: domain.AuthAudience, JTI: "test-jti", IssuedAt: now, ExpiresAt: now + 60, Permissions: []string{}}
	first, _ := identitysigner.New("issuer", "old", key1)
	second, _ := identitysigner.New("issuer", "new", key2)
	one, e := first.Sign(t.Context(), claims)
	if e != nil {
		t.Fatal(e)
	}
	two, e := second.Sign(t.Context(), claims)
	if e != nil {
		t.Fatal(e)
	}
	settings := config.UserIdentityConfig{Issuer: "issuer", PublicKeyPEMByKID: map[string][]byte{"old": pub(key1), "new": pub(key2)}, MaxTTL: 5 * time.Minute, ClockSkew: 30 * time.Second}
	verifier, e := transport.NewUserIdentityVerifier(settings)
	if e != nil {
		t.Fatal(e)
	}
	for _, token := range []string{one, two} {
		if _, e := verifier.Verify(token); e != nil {
			t.Fatal("overlapping key rejected", e)
		}
	}
	delete(settings.PublicKeyPEMByKID, "old")
	verifier, e = transport.NewUserIdentityVerifier(settings)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := verifier.Verify(one); e == nil {
		t.Fatal("removed key accepted")
	}
	if _, e := verifier.Verify(two); e != nil {
		t.Fatal(e)
	}
	settings.PublicKeyPEMByKID["new"] = pub(key1)
	verifier, _ = transport.NewUserIdentityVerifier(settings)
	if _, e := verifier.Verify(two); e == nil {
		t.Fatal("wrong public key accepted")
	}
	start := time.Now()
	for range 30 {
		if _, e := second.Sign(t.Context(), claims); e != nil {
			t.Fatal(e)
		}
	}
	t.Logf("LOCAL ONLY: production RSA2048 signer 30 iterations mean=%s", time.Since(start)/30)
}
