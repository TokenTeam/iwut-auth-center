package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestPasswordGateRequiresIndependentKeyAndPinnedPolicy(t *testing.T) {
	env := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if p, err := loadPassword(lookup, nil, nil, nil); p != nil || err != nil {
		t.Fatal("default not closed")
	}
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	env["AUTH_PASSWORD_ENABLED"] = "true"
	email := &EmailBinding{HMACKey: bytes.Repeat([]byte{3}, 32)}
	login := &EmailBinding{HMACKey: bytes.Repeat([]byte{4}, 32)}
	if _, err := loadPassword(lookup, &UserEndpoints{}, email, login); err == nil {
		t.Fatal("missing parameters accepted")
	}
	for k, v := range map[string]string{"AUTH_PASSWORD_OPERATION_HMAC_KEY": key(5), "AUTH_PASSWORD_BLOCKLIST_FILE": "/test/blocklist.txt", "AUTH_PASSWORD_BLOCKLIST_VERSION": "fixture", "AUTH_PASSWORD_BLOCKLIST_SOURCE": "TEST ONLY", "AUTH_PASSWORD_BLOCKLIST_SHA256": strings.Repeat("0", 64), "AUTH_PASSWORD_READINESS_CONFIRMED": "true"} {
		env[k] = v
	}
	if p, err := loadPassword(lookup, &UserEndpoints{}, email, login); err != nil || p == nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ k, v string }{{"AUTH_PASSWORD_OPERATION_HMAC_KEY", key(3)}, {"AUTH_PASSWORD_OPERATION_HMAC_KEY", key(4)}, {"AUTH_PASSWORD_OPERATION_HMAC_KEY", "bad"}, {"AUTH_PASSWORD_BLOCKLIST_SHA256", strings.Repeat("A", 64)}, {"AUTH_PASSWORD_READINESS_CONFIRMED", "false"}, {"AUTH_PASSWORD_ARGON_MEMORY_KIB", "1"}, {"AUTH_PASSWORD_ARGON_ITERATIONS", "7"}, {"AUTH_PASSWORD_ARGON_PARALLELISM", "0"}} {
		old, exists := env[test.k]
		env[test.k] = test.v
		if _, err := loadPassword(lookup, &UserEndpoints{}, email, login); err == nil {
			t.Fatal("accepted", test.k)
		}
		if exists {
			env[test.k] = old
		} else {
			delete(env, test.k)
		}
	}
	if _, err := loadPassword(lookup, &UserEndpoints{}, nil, nil); err == nil {
		t.Fatal("no delivery dependency")
	}
	env["AUTH_PASSWORD_ENABLED"] = "false"
	if p, err := loadPassword(lookup, nil, nil, nil); p != nil || err != nil {
		t.Fatal("disabled gate depends on secrets")
	}
}
