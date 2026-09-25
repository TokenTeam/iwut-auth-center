package config

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEmailLoginIndependentConfigurationGate(t *testing.T) {
	user := &UserEndpoints{Association: Association{Current: AssociationKey{Version: "v1", Encrypt: bytes.Repeat([]byte{1}, 32), Lookup: bytes.Repeat([]byte{2}, 32)}}}
	env := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	load := func(u *UserEndpoints) (*EmailBinding, error) {
		return loadEmailCapability(lookup, u, "AUTH_EMAIL_LOGIN_ENABLED", "AUTH_EMAIL_LOGIN_CODE_KEY")
	}
	if c, e := load(nil); e != nil || c != nil {
		t.Fatal("default must be off")
	}
	env["AUTH_EMAIL_LOGIN_ENABLED"] = "true"
	if _, e := load(nil); e == nil {
		t.Fatal("enabled without user endpoints")
	}
	for k, v := range map[string]string{"AUTH_EMAIL_LOGIN_CODE_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "AUTH_SMTP_ADDR": "smtp.example.test:465", "AUTH_SMTP_FROM": "auth@example.test", "AUTH_SMTP_TLS_MODE": "implicit_tls"} {
		env[k] = v
	}
	if c, e := load(user); e != nil || c == nil {
		t.Fatal("login-only must not require binding HMAC", e)
	}
	if c, e := loadEmailBinding(lookup, user); e != nil || c != nil {
		t.Fatal("login enabled binding")
	}
	for _, bad := range []struct{ k, v string }{{"AUTH_EMAIL_LOGIN_ENABLED", "bad"}, {"AUTH_EMAIL_LOGIN_CODE_KEY", ""}, {"AUTH_EMAIL_LOGIN_CODE_KEY", base64.StdEncoding.EncodeToString(user.Association.Current.Encrypt)}, {"AUTH_EMAIL_LOGIN_CODE_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 31))}, {"AUTH_SMTP_TLS_MODE", "plaintext"}} {
		old := env[bad.k]
		env[bad.k] = bad.v
		if _, e := load(user); e == nil {
			t.Fatalf("accepted invalid %s", bad.k)
		}
		env[bad.k] = old
	}
}
