package config

import (
	"testing"
	"time"
)

func TestAuthenticationConfigurationRequiresExplicitIdentityAndTTL(t *testing.T) {
	values := map[string]string{"AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "720h"}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	c, err := LoadAuthentication(lookup)
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionTTL != 720*time.Hour || c.MaxPending != 10000 || c.MaxFailures != 5 || c.MaxMessageBytes != 16384 || c.BeginGlobal != 600 || c.CompleteGlobal != 1200 || c.BeginSource != 30 || c.CompleteLocator != 60 {
		t.Fatal("incorrect fixed defaults", c)
	}
	for _, test := range []struct{ key, value string }{
		{"AUTH_SESSION_TTL", ""}, {"AUTH_SESSION_TTL", "0s"}, {"AUTH_SESSION_TTL", "-1h"}, {"AUTH_SESSION_TTL", "0.1ms"}, {"AUTH_SESSION_TTL", "invalid"},
		{"AUTH_AUTHENTICATION_SERVICE_ID", ""}, {"AUTH_AUTHENTICATION_SERVICE_ID", "prod test"}, {"AUTH_AUTHENTICATION_SERVICE_ID", "汉字"},
		{"AUTH_MAX_FAILED_ATTEMPTS", "0"}, {"AUTH_MAX_PENDING_OPERATIONS", "-1"}, {"AUTH_RATE_MAX_BUCKETS", "unlimited"}, {"AUTH_BEGIN_GLOBAL_PER_MINUTE", "10000001"},
	} {
		old, exists := values[test.key]
		values[test.key] = test.value
		if _, err := LoadAuthentication(lookup); err == nil {
			t.Fatalf("invalid config accepted: %s", test.key)
		}
		if exists {
			values[test.key] = old
		} else {
			delete(values, test.key)
		}
	}
	delete(values, "AUTH_SESSION_TTL")
	if _, err := LoadAuthentication(lookup); err == nil {
		t.Fatal("implicit TTL accepted")
	}
}
