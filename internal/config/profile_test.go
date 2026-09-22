package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileConfigurationRequiresExplicitSource(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	if _, e := ParseProfileConfig(lookup); e == nil {
		t.Fatal("missing catalog accepted")
	}
	file := filepath.Join(t.TempDir(), "fields.json")
	if e := os.WriteFile(file, []byte(`{"definitions":[]}`), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := ParseProfileConfig(func(key string) (string, bool) { return file, key == "AUTH_PROFILE_CATALOG_FILE" })
	if e != nil || string(c.JSON) != `{"definitions":[]}` {
		t.Fatal("explicit source not retained", e)
	}
}
func TestUserIdentityConfigRejectsDuplicateKey(t *testing.T) {
	env := map[string]string{"AUTH_USER_IDENTITY_ISSUER": "test", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": `{"a":"one","a":"two"}`}
	_, e := ParseUserIdentityConfig(func(key string) (string, bool) { v, ok := env[key]; return v, ok })
	if e == nil || e.Error() != "duplicate user identity kid" {
		t.Fatalf("duplicate key not rejected: %v", e)
	}
}
