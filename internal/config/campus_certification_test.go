package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCampusConfigurationDefaultGateAndRequiredSettings(t *testing.T) {
	env := map[string]string{}
	lookup := func(key string) (string, bool) { value, ok := env[key]; return value, ok }
	if c, err := loadCampusCertification(lookup, nil); err != nil || c != nil {
		t.Fatal("campus default must be disabled")
	}
	env["AUTH_CAMPUS_CERTIFICATION_ENABLED"] = "true"
	if _, err := loadCampusCertification(lookup, nil); err == nil {
		t.Fatal("campus without USER enabled")
	}
	env["AUTH_EMAIL_BINDING_HMAC_KEY"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	env["AUTH_SMTP_ADDR"] = "smtp.example.test:465"
	env["AUTH_SMTP_FROM"] = "auth@example.test"
	env["AUTH_SMTP_TLS_MODE"] = "implicit_tls"
	c, err := loadCampusCertification(lookup, &UserEndpoints{})
	if err != nil || c == nil || c.OwnerHourly != 5 || c.EmailHourly != 5 || c.SourceHourly != 20 {
		t.Fatal("valid campus shared SMTP/quota config", err)
	}
	for _, bad := range []struct{ key, value string }{{"AUTH_CAMPUS_CERTIFICATION_ENABLED", "bad"}, {"AUTH_EMAIL_BINDING_HMAC_KEY", "not-base64"}, {"AUTH_EMAIL_BINDING_HMAC_KEY", base64.StdEncoding.EncodeToString(make([]byte, 31))}, {"AUTH_SMTP_TLS_MODE", "plaintext"}, {"AUTH_EMAIL_MAX_BUCKETS", "0"}} {
		old, exists := env[bad.key]
		env[bad.key] = bad.value
		if _, err = loadCampusCertification(lookup, &UserEndpoints{}); err == nil {
			t.Fatalf("accepted invalid %s", bad.key)
		}
		if exists {
			env[bad.key] = old
		} else {
			delete(env, bad.key)
		}
	}
	env["AUTH_CAMPUS_CERTIFICATION_ENABLED"] = "false"
	delete(env, "AUTH_EMAIL_BINDING_HMAC_KEY")
	if c, err = loadCampusCertification(lookup, nil); err != nil || c != nil {
		t.Fatal("disabled gate must not require key")
	}
}

func TestCampusConfigurationUsesAddKeyAndIgnoresRetiredCampusKey(t *testing.T) {
	dir := t.TempDir()
	catalog, keyFile := filepath.Join(dir, "profile.json"), filepath.Join(dir, "public.pem")
	for path, value := range map[string]string{catalog: `{"definitions":[]}`, keyFile: "parsed by identity adapter"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	env := map[string]string{
		UserEndpointsEnabledEnv: "true", "AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h",
		"AUTH_PROFILE_CATALOG_FILE": catalog, "AUTH_USER_IDENTITY_ISSUER": "test", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": `{"test":"` + keyFile + `"}`,
		"AUTH_EMAIL_BINDING_ENABLED": "true", "AUTH_EMAIL_BINDING_HMAC_KEY": key(3), "AUTH_EMAIL_LOGIN_ENABLED": "true", "AUTH_EMAIL_LOGIN_CODE_KEY": key(4),
		"AUTH_CAMPUS_CERTIFICATION_ENABLED": "true", "AUTH_CAMPUS_CERTIFICATION_CODE_KEY": key(5),
		"AUTH_SMTP_ADDR": "smtp.example.test:465", "AUTH_SMTP_FROM": "auth@example.test", "AUTH_SMTP_TLS_MODE": "implicit_tls",
		"AUTH_ASSOC_ENCRYPT_KEY": "malformed-retired-key",
	}
	env["AUTH_PASSWORD_ENABLED"] = "true"
	env["AUTH_PASSWORD_OPERATION_HMAC_KEY"] = key(42)
	env["AUTH_PASSWORD_BLOCKLIST_FILE"] = "/test-only/blocklist.txt"
	env["AUTH_PASSWORD_BLOCKLIST_VERSION"] = "fixture-v1"
	env["AUTH_PASSWORD_BLOCKLIST_SOURCE"] = "TEST ONLY"
	env["AUTH_PASSWORD_BLOCKLIST_SHA256"] = strings.Repeat("0", 64)
	env["AUTH_PASSWORD_READINESS_CONFIRMED"] = "true"
	lookup := withRequiredServiceCallers(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if cfg, err := Load(lookup); err != nil || cfg.CampusCertification == nil {
		t.Fatalf("valid independent keys: %v", err)
	}
	for _, existing := range []byte{3, 4} {
		env["AUTH_CAMPUS_CERTIFICATION_CODE_KEY"] = key(existing)
		if cfg, err := Load(lookup); err != nil || !bytes.Equal(cfg.CampusCertification.HMACKey, cfg.EmailBinding.HMACKey) {
			t.Fatal("campus alias did not use ADD key", err)
		}
	}
	env["AUTH_CAMPUS_CERTIFICATION_ENABLED"] = "false"
	if cfg, err := Load(lookup); err != nil || cfg.CampusCertification != nil {
		t.Fatalf("disabled key must not become dependency: %v", err)
	}
}
