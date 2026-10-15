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
	env := map[string]string{"AUTH_PROFILE_CATALOG_FILE": file, "AUTH_ACADEMIC_CALENDAR_FILE": filepath.Join(t.TempDir(), "missing-is-ignored.json")}
	c, e := ParseProfileConfig(func(key string) (string, bool) { value, ok := env[key]; return value, ok })
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
