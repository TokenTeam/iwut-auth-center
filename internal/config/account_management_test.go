package config

import "testing"

func TestAccountManagementGateAndBounds(t *testing.T) {
	for _, tc := range []struct {
		values    map[string]string
		user      *UserEndpoints
		wantError bool
		enabled   bool
	}{{map[string]string{}, nil, false, false}, {map[string]string{"AUTH_ACCOUNT_MANAGEMENT_ENDPOINTS_ENABLED": "true"}, nil, true, false}, {map[string]string{"AUTH_ACCOUNT_MANAGEMENT_ENDPOINTS_ENABLED": "true"}, &UserEndpoints{}, false, true}, {map[string]string{"AUTH_ACCOUNT_MANAGEMENT_ENDPOINTS_ENABLED": "true", "AUTH_ACCOUNT_MANAGEMENT_MAX_BUCKETS": "0"}, &UserEndpoints{}, true, false}} {
		c, e := loadAccountManagement(func(k string) (string, bool) { v, ok := tc.values[k]; return v, ok }, tc.user)
		if (e != nil) != tc.wantError || (c != nil) != tc.enabled {
			t.Fatal(c, e)
		}
	}
}
