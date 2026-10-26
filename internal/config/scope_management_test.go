package config

import "testing"

func TestScopeManagementConfigurationDefaultOffAndDependencies(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	if enabled, err := loadScopeManagement(lookup, nil, nil, nil); err != nil || enabled {
		t.Fatalf("default=%v,%v", enabled, err)
	}
	for _, raw := range []string{"", "yes", "invalid"} {
		if _, err := loadScopeManagement(func(string) (string, bool) { return raw, true }, nil, nil, nil); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	lookup = func(string) (string, bool) { return "true", true }
	for _, config := range []struct {
		user     *UserEndpoints
		issuance *IdentityIssuance
		oauth    *OAuth
	}{{}, {user: &UserEndpoints{}}, {user: &UserEndpoints{}, issuance: &IdentityIssuance{}}, {user: &UserEndpoints{}, issuance: &IdentityIssuance{}, oauth: &OAuth{}}} {
		if _, err := loadScopeManagement(lookup, config.user, config.issuance, config.oauth); err == nil {
			t.Fatal("accepted missing dependency")
		}
	}
	if enabled, err := loadScopeManagement(lookup, &UserEndpoints{}, &IdentityIssuance{}, &OAuth{CatalogFile: "providers.json"}); err != nil || !enabled {
		t.Fatalf("enabled=%v,%v", enabled, err)
	}
}
