package config

import "testing"

func TestLoadApplicationUserStorageIsDefaultClosedAndRequiresDependencies(t *testing.T) {
	lookup := func(values map[string]string) LookupEnv {
		return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	}
	if value, err := loadApplicationUserStorage(lookup(nil), nil, nil); err != nil || value != nil {
		t.Fatalf("default = %#v, %v", value, err)
	}
	if _, err := loadApplicationUserStorage(lookup(map[string]string{ApplicationUserStorageEnabledEnv: "true"}), nil, nil); err == nil {
		t.Fatal("enabled storage accepted without OAuth/user endpoints")
	}
	if _, err := loadApplicationUserStorage(lookup(map[string]string{ApplicationUserStorageEnabledEnv: "true"}), &OAuth{}, &UserEndpoints{}); err == nil {
		t.Fatal("enabled storage accepted without resource readiness")
	}
	value, err := loadApplicationUserStorage(lookup(map[string]string{ApplicationUserStorageEnabledEnv: "true"}), &OAuth{ResourceScopesReady: true}, &UserEndpoints{})
	if err != nil || value == nil || !value.Enabled {
		t.Fatalf("enabled = %#v, %v", value, err)
	}
}
