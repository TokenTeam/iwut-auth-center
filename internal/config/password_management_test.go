package config

import "testing"

func TestPasswordManagementExplicitGate(t *testing.T) {
	values := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := values[k]; return v, ok }
	if enabled, err := loadPasswordManagement(lookup, nil); enabled || err != nil {
		t.Fatal(enabled, err)
	}
	values["AUTH_PASSWORD_MANAGEMENT_ENABLED"] = "true"
	if _, err := loadPasswordManagement(lookup, nil); err == nil {
		t.Fatal("missing password runtime accepted")
	}
	if enabled, err := loadPasswordManagement(lookup, &Password{}); !enabled || err != nil {
		t.Fatal(enabled, err)
	}
}
