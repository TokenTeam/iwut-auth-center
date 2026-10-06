package transport

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"iwut-auth-center/internal/config"
)

type fixedServiceVerifierClock struct{ now time.Time }

func (clock fixedServiceVerifierClock) Now() time.Time { return clock.now }

func TestServiceIdentityVerifier_VerifiesRegisteredCallerAndRejectsInvalidClaims(t *testing.T) {
	now := time.Date(2026, time.September, 22, 1, 2, 3, 0, time.UTC)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewServiceIdentityVerifier(config.Config{
		ServiceCallers: []config.ServiceCallerRegistration{{
			ServiceID: "app-center", Status: "ACTIVE",
			PublicKeyPEMByKID: map[string][]byte{"key-1": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})},
			Permissions: []string{
				PermissionDeveloperStatusRead,
				PermissionApplicationClosureApply,
				PermissionApplicationClosureRead,
			},
			SystemPrincipalPurposes: []string{PurposeAppCenterReviewAutoRejection},
		}},
		ServiceIdentityMaxTTL: time.Minute, ServiceIdentityClockSkew: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServiceIdentityVerifier() error = %v", err)
	}
	verifier.clock = fixedServiceVerifierClock{now: now}

	valid := signServiceIdentity(t, key, "key-1", map[string]any{
		"iss": "app-center", "sub": "app-center", "aud": "iwut-auth-center",
		"iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "one",
	})
	identity, err := verifier.Verify(valid)
	if err != nil || identity.ServiceID != "app-center" || !identity.HasPermission(PermissionDeveloperStatusRead) ||
		!identity.HasPermission(PermissionApplicationClosureApply) || !identity.HasPermission(PermissionApplicationClosureRead) ||
		!identity.MayResolveSystemPrincipal(PurposeAppCenterReviewAutoRejection) {
		t.Fatalf("Verify(valid) = (%#v, %v)", identity, err)
	}

	tests := map[string]string{
		"wrong audience": signServiceIdentity(t, key, "key-1", map[string]any{
			"iss": "app-center", "sub": "app-center", "aud": "another-service", "iat": now.Unix(),
			"nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "two",
		}),
		"unknown kid": signServiceIdentity(t, key, "unknown", map[string]any{
			"iss": "app-center", "sub": "app-center", "aud": "iwut-auth-center", "iat": now.Unix(),
			"nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "three",
		}),
		"excessive ttl": signServiceIdentity(t, key, "key-1", map[string]any{
			"iss": "app-center", "sub": "app-center", "aud": "iwut-auth-center", "iat": now.Unix(),
			"nbf": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": "four",
		}),
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(token); err == nil {
				t.Fatal("Verify() error = nil")
			}
		})
	}
}

func signServiceIdentity(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	headerPart := base64.RawURLEncoding.EncodeToString(header)
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(headerPart + "." + payloadPart))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return headerPart + "." + payloadPart + "." + base64.RawURLEncoding.EncodeToString(signature)
}
