package oauthcrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestPKCEAndPurposeSeparatedSigning(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 2048)
	b, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, e := New(Key{"same", a}, Key{"same", b}, nil); e == nil {
		t.Fatal("same kid")
	}
	if _, e := New(Key{"a", a}, Key{"b", a}, nil); e == nil {
		t.Fatal("same key")
	}
	c, e := New(Key{"oidc", a}, Key{"delegation", b}, nil)
	if e != nil {
		t.Fatal(e)
	}
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if !c.VerifyPKCE(challenge, verifier) || c.VerifyPKCE(challenge, verifier+"=") || c.VerifyPKCE(challenge, "wrong") {
		t.Fatal("RFC7636 vector")
	}
	raw, e := c.Random()
	if e != nil || !c.ValidOpaque(raw) || c.ValidOpaque(raw+"=") {
		t.Fatal("opaque canonical form")
	}
	if c.Digest("access", raw) == c.Digest("refresh", raw) {
		t.Fatal("cross-purpose digest")
	}
	token, e := c.SignID(map[string]any{"sub": "pairwise", "aud": "client"})
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&a.PublicKey, crypto.SHA256, hash[:], sig) != nil || rsa.VerifyPKCS1v15(&b.PublicKey, crypto.SHA256, hash[:], sig) == nil {
		t.Fatal("signing key isolation")
	}
	encoded, _ := json.Marshal(c.JWKS())
	if strings.Contains(string(encoded), "delegation") || strings.Contains(string(encoded), `"d"`) {
		t.Fatal("JWKS leaked private or delegation key")
	}
}
