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
	"google.golang.org/protobuf/encoding/protowire"
	"iwut-auth-center/internal/config"
	"testing"
	"time"
)

func userKey(t *testing.T) (*rsa.PrivateKey, *UserIdentityVerifier) {
	t.Helper()
	k, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	data, e := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	v, e := NewUserIdentityVerifier(config.UserIdentityConfig{Issuer: "test-auth", PublicKeyPEMByKID: map[string][]byte{"k1": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data})}, MaxTTL: 5 * time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	return k, v
}
func signUser(t *testing.T, k *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	p, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	digest := sha256.Sum256([]byte(input))
	sig, e := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func userClaims(id string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{"account_revision": "1", "iss": "test-auth", "sub": id, "aud": "iwut-auth-center", "iat": now, "nbf": now, "exp": now + 60, "jti": "t1"}
}
func TestUserIdentityClaimsAndSignature(t *testing.T) {
	k, v := userKey(t)
	claims := userClaims("user1")
	token := signUser(t, k, claims)
	if id, e := v.Verify(token); e != nil || id != "user1" {
		t.Fatal("valid user rejected", e)
	}
	for _, change := range []struct {
		key   string
		value any
	}{{"account_revision", nil}, {"account_revision", float64(1)}, {"account_revision", "0"}, {"account_revision", "01"}, {"account_revision", "+1"}, {"account_revision", "9223372036854775808"}, {"aud", "iwut-app-center"}, {"iss", "other"}, {"sub", ""}, {"jti", ""}, {"exp", time.Now().Unix() - 1}, {"exp", time.Now().Unix() + 10000}, {"developer_status", "UNKNOWN"}, {"permissions", []string{"x", "x"}}, {"permissions", nil}, {"permissions", []string{" x"}}, {"iat", nil}} {
		c := userClaims("user1")
		c[change.key] = change.value
		if _, e := v.Verify(signUser(t, k, c)); e == nil {
			t.Fatalf("invalid %s accepted", change.key)
		}
	}
	for _, bad := range []string{"Bearer " + token, token + " ", token[:len(token)-4] + "AAAA", "", token + ".extra"} {
		if _, e := v.Verify(bad); e == nil {
			t.Fatal("malformed token accepted")
		}
	}
}
func TestProfileRawOneofBranches(t *testing.T) {
	value := protowire.AppendTag(nil, 2, protowire.VarintType)
	value = protowire.AppendVarint(value, 0)
	value = protowire.AppendTag(value, 3, protowire.VarintType)
	value = protowire.AppendVarint(value, 0)
	assignment := protowire.AppendTag(nil, 2, protowire.BytesType)
	assignment = protowire.AppendBytes(assignment, value)
	request := protowire.AppendTag(nil, 2, protowire.BytesType)
	request = protowire.AppendBytes(request, assignment)
	if validateProfileWire(request, 0) == nil {
		t.Fatal("multiple oneof branches silently accepted")
	}
}
