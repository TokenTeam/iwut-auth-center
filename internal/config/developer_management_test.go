package config

import "testing"

func TestDeveloperManagementDefaultClosedAndRequiresUserEndpoints(t *testing.T) {
	env := map[string]string{}
	lookup := func(k string) (string, bool) { s, ok := env[k]; return s, ok }
	c, e := loadDeveloperManagement(lookup, nil)
	if c != nil || e != nil {
		t.Fatal(c, e)
	}
	env["AUTH_DEVELOPER_MANAGEMENT_ENDPOINTS_ENABLED"] = "true"
	if _, e = loadDeveloperManagement(lookup, nil); e == nil {
		t.Fatal("user endpoint gate")
	}
	c, e = loadDeveloperManagement(lookup, &UserEndpoints{})
	if e != nil || c.RecoveryReady || c.ReadPerMinute != 60 || c.WritePerMinute != 10 {
		t.Fatal(c, e)
	}
	env["AUTH_EMAIL_RECOVERY_READY"] = "true"
	env["AUTH_EMAIL_LOGIN_ENABLED"] = "true"
	c, e = loadDeveloperManagement(lookup, &UserEndpoints{})
	if e != nil || !c.RecoveryReady {
		t.Fatal(c, e)
	}
	env["AUTH_DEVELOPER_MANAGEMENT_MAX_BUCKETS"] = "0"
	if _, e = loadDeveloperManagement(lookup, &UserEndpoints{}); e == nil {
		t.Fatal("zero buckets")
	}
}
