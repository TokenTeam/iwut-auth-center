package config

import "testing"

func TestDeveloperApplicationConfiguration(t *testing.T) {
	env := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if c, e := loadDeveloperApplication(lookup, nil); c != nil || e != nil {
		t.Fatal(c, e)
	}
	env["AUTH_DEVELOPER_APPLICATION_ENABLED"] = "true"
	if _, e := loadDeveloperApplication(lookup, nil); e == nil {
		t.Fatal("user endpoints required")
	}
	c, e := loadDeveloperApplication(lookup, &UserEndpoints{})
	if e != nil || c == nil || c.RecoveryReady {
		t.Fatal(c, e)
	}
	env["AUTH_EMAIL_RECOVERY_READY"] = "true"
	c, e = loadDeveloperApplication(lookup, &UserEndpoints{})
	if e != nil || !c.RecoveryReady {
		t.Fatal(c, e)
	}
	for _, tc := range []struct{ k, v string }{{"AUTH_DEVELOPER_APPLICATION_ENABLED", "bad"}, {"AUTH_EMAIL_RECOVERY_READY", "bad"}, {"AUTH_DEVELOPER_GLOBAL_PER_MINUTE", "0"}, {"AUTH_DEVELOPER_SOURCE_PER_MINUTE", "-1"}, {"AUTH_DEVELOPER_ACCOUNT_PER_MINUTE", "invalid"}, {"AUTH_DEVELOPER_MAX_BUCKETS", "1000001"}} {
		old, ok := env[tc.k]
		env[tc.k] = tc.v
		if _, e := loadDeveloperApplication(lookup, &UserEndpoints{}); e == nil {
			t.Fatal(tc)
		}
		if ok {
			env[tc.k] = old
		} else {
			delete(env, tc.k)
		}
	}
}
