package config

import "testing"

func TestCredentialManagementGate(t *testing.T) {
	env := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if c, err := loadCredentialManagement(lookup, nil, nil); c != nil || err != nil {
		t.Fatal(c, err)
	}
	env["AUTH_CREDENTIAL_MANAGEMENT_ENABLED"] = "true"
	if _, err := loadCredentialManagement(lookup, &UserEndpoints{}, nil); err == nil {
		t.Fatal("missing password accepted")
	}
	c, err := loadCredentialManagement(lookup, &UserEndpoints{}, &Password{})
	if err != nil || c.GlobalPerMinute != 600 || c.AccountPerMinute != 30 {
		t.Fatal(c, err)
	}
	env["AUTH_CREDENTIAL_MANAGEMENT_MAX_BUCKETS"] = "0"
	if _, err = loadCredentialManagement(lookup, &UserEndpoints{}, &Password{}); err == nil {
		t.Fatal("zero budget accepted")
	}
}
