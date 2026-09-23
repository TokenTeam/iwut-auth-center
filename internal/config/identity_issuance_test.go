package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"
)

func TestIdentityIssuanceConfiguration(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	users := &UserEndpoints{UserIdentity: UserIdentityConfig{Issuer: "issuer", PublicKeyPEMByKID: map[string][]byte{"key": public}, MaxTTL: 5 * time.Minute}}
	baseline := map[string]string{IdentityIssuanceEnabledEnv: "true", "AUTH_USER_IDENTITY_SIGNING_KID": "key", "AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64": base64.StdEncoding.EncodeToString(private)}
	for _, tc := range []struct {
		name, key, value string
		bad              bool
	}{{"default", "", "", false}, {"one", "AUTH_USER_IDENTITY_TTL", "1s", false}, {"max", "AUTH_USER_IDENTITY_TTL", "300s", false}, {"too long", "AUTH_USER_IDENTITY_TTL", "301s", true}, {"fraction", "AUTH_USER_IDENTITY_TTL", "1.5s", true}, {"zero", "AUTH_USER_IDENTITY_TTL", "0s", true}, {"key", "AUTH_USER_IDENTITY_SIGNING_KID", "unknown", true}, {"base64 whitespace", "AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64", baseline["AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64"] + "\n", true}, {"missing", "AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64", "", true}, {"bool", IdentityIssuanceEnabledEnv, "invalid", true}} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			for k, v := range baseline {
				env[k] = v
			}
			if tc.key != "" {
				env[tc.key] = tc.value
			}
			c, e := loadIdentityIssuance(func(k string) (string, bool) { v, ok := env[k]; return v, ok }, users, nil)
			if (e != nil) != tc.bad {
				t.Fatalf("config %v %v", c, e)
			}
		})
	}
	lookup := func(k string) (string, bool) { v, ok := baseline[k]; return v, ok }
	if _, e := loadIdentityIssuance(lookup, nil, nil); e == nil {
		t.Fatal("enabled without users")
	}
	if _, e := loadIdentityIssuance(lookup, users, []ServiceCallerRegistration{{PublicKeyPEMByKID: map[string][]byte{"other-name": public}}}); e == nil {
		t.Fatal("service key reused")
	}
	users.UserIdentity.MaxTTL = 30 * time.Second
	if _, e := loadIdentityIssuance(lookup, users, nil); e == nil {
		t.Fatal("verifier TTL mismatch")
	}
	if _, e := loadIdentityIssuance(func(k string) (string, bool) {
		if k == IdentityIssuanceEnabledEnv {
			return "false", true
		}
		return "", false
	}, nil, nil); e != nil {
		t.Fatal(e)
	}
}
func TestIdentityAudienceConfiguration(t *testing.T) {
	for _, tc := range []struct {
		p, a []string
		bad  bool
	}{{nil, nil, false}, {[]string{IdentityIssuePermission}, []string{"iwut-auth-center"}, false}, {[]string{IdentityIssuePermission}, nil, true}, {nil, []string{"iwut-auth-center"}, true}, {[]string{IdentityIssuePermission}, []string{"iwut-auth-center", "iwut-auth-center"}, true}, {[]string{IdentityIssuePermission}, []string{"anything"}, true}} {
		if err := validateIdentityAudiences(tc.p, tc.a); (err != nil) != tc.bad {
			t.Fatal(tc, err)
		}
	}
}
