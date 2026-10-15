package config

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEmailConfigurationGate(t *testing.T) {
	user := &UserEndpoints{}
	env := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if c, e := loadEmailBinding(lookup, nil); e != nil || c != nil {
		t.Fatal("default gate")
	}
	env["AUTH_EMAIL_BINDING_ENABLED"] = "true"
	if _, e := loadEmailBinding(lookup, nil); e == nil {
		t.Fatal("enabled without user endpoints")
	}
	for k, v := range map[string]string{"AUTH_EMAIL_BINDING_HMAC_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), "AUTH_SMTP_ADDR": "smtp.example.test:465", "AUTH_SMTP_FROM": "auth@example.test", "AUTH_SMTP_TLS_MODE": "implicit_tls"} {
		env[k] = v
	}
	if c, e := loadEmailBinding(lookup, user); e != nil || c.OwnerHourly != 5 || c.EmailHourly != 5 || c.SourceHourly != 20 {
		t.Fatal("valid config", e)
	}
	for _, test := range []struct{ k, v string }{{"AUTH_EMAIL_BINDING_ENABLED", "bad"}, {"AUTH_EMAIL_BINDING_HMAC_KEY", "bad"}, {"AUTH_SMTP_ADDR", "smtp.test"}, {"AUTH_SMTP_ADDR", "smtp.test:0"}, {"AUTH_SMTP_FROM", "auth@example.test\r\nBcc: x@example.test"}, {"AUTH_SMTP_TLS_MODE", "plaintext"}, {"AUTH_SMTP_TIMEOUT", "0s"}, {"AUTH_SMTP_USERNAME", "unpaired"}, {"AUTH_SMTP_CA_FILE", "/no/such/file"}, {"AUTH_EMAIL_OWNER_HOURLY", "0"}, {"AUTH_EMAIL_MAX_BUCKETS", "-1"}} {
		old, ok := env[test.k]
		env[test.k] = test.v
		if _, e := loadEmailBinding(lookup, user); e == nil {
			t.Fatalf("accepted invalid %s", test.k)
		}
		if ok {
			env[test.k] = old
		} else {
			delete(env, test.k)
		}
	}
}
