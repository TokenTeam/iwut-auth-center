package config

import "testing"

func TestPlatformAdministratorDefaultClosedAndReadiness(t *testing.T) {
	env := map[string]string{}
	lookup := func(k string) (string, bool) { s, ok := env[k]; return s, ok }
	c, e := loadPlatformAdministrator(lookup, nil)
	if e != nil || c != nil {
		t.Fatal(c, e)
	}
	env["AUTH_PLATFORM_ADMIN_ENDPOINTS_ENABLED"] = "true"
	if _, e = loadPlatformAdministrator(lookup, nil); e == nil {
		t.Fatal("user gate missing")
	}
	c, e = loadPlatformAdministrator(lookup, &UserEndpoints{})
	if e != nil || c.RecoveryReady || c.ReadPerMinute != 60 || c.WritePerMinute != 10 {
		t.Fatal(c, e)
	}
	env["AUTH_EMAIL_RECOVERY_READY"] = "true"
	c, e = loadPlatformAdministrator(lookup, &UserEndpoints{})
	if e != nil || c.RecoveryReady {
		t.Fatal(c, e)
	}
	env["AUTH_EMAIL_LOGIN_ENABLED"] = "true"
	c, e = loadPlatformAdministrator(lookup, &UserEndpoints{})
	if e != nil || !c.RecoveryReady {
		t.Fatal(c, e)
	}
	env["AUTH_PLATFORM_ADMIN_MAX_BUCKETS"] = "0"
	if _, e = loadPlatformAdministrator(lookup, &UserEndpoints{}); e == nil {
		t.Fatal("unbounded bucket configuration")
	}
}
