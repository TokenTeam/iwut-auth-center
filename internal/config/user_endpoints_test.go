package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestUserEndpointsFailClosedAndRequireExplicitEnable(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	if c, err := loadUserEndpoints(lookup); c != nil || err != nil {
		t.Fatal(c, err)
	}
	env := map[string]string{UserEndpointsEnabledEnv: "true"}
	lookup = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if _, err := loadUserEndpoints(lookup); err == nil {
		t.Fatal("enabled without required configuration")
	}
	dir := t.TempDir()
	catalog := filepath.Join(dir, "catalog.json")
	key := filepath.Join(dir, "public.pem")
	for path, data := range map[string]string{catalog: `{"definitions":[]}`, key: "parsed by identity adapter"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	env["AUTH_AUTHENTICATION_SERVICE_ID"] = "iwut-auth-center:test"
	env["AUTH_SESSION_TTL"] = "24h"
	env["AUTH_ASSOC_KEY_VERSION"] = "v1"
	a, b := make([]byte, 32), make([]byte, 32)
	a[0] = 1
	b[0] = 2
	env["AUTH_ASSOC_ENCRYPT_KEY"] = base64.StdEncoding.EncodeToString(a)
	env["AUTH_ASSOC_LOOKUP_KEY"] = base64.StdEncoding.EncodeToString(b)
	env["AUTH_PROFILE_CATALOG_FILE"] = catalog
	env["AUTH_USER_IDENTITY_ISSUER"] = "test-issuer"
	env["AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON"] = `{"test":"` + key + `"}`
	if c, err := loadUserEndpoints(lookup); err != nil || c == nil {
		t.Fatal(c, err)
	}
	env[UserEndpointsEnabledEnv] = "anything"
	if _, err := loadUserEndpoints(lookup); err == nil {
		t.Fatal("invalid enable flag accepted")
	}
	env[UserEndpointsEnabledEnv] = "false"
	if c, err := loadUserEndpoints(lookup); c != nil || err != nil {
		t.Fatal(c, err)
	}
}
