package config

import "testing"

func TestSessionManagementConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name          string
		env           map[string]string
		user          *UserEndpoints
		enabled, fail bool
	}{
		{"default off", nil, nil, false, false},
		{"requires user", map[string]string{"AUTH_SESSION_MANAGEMENT_ENABLED": "true"}, nil, false, true},
		{"enabled defaults", map[string]string{"AUTH_SESSION_MANAGEMENT_ENABLED": "true"}, &UserEndpoints{}, true, false},
		{"invalid flag", map[string]string{"AUTH_SESSION_MANAGEMENT_ENABLED": "yes"}, nil, false, true},
		{"bad disabled config", map[string]string{"AUTH_SESSION_MANAGEMENT_MAX_BUCKETS": "0"}, nil, false, true},
		{"bounded", map[string]string{"AUTH_SESSION_MANAGEMENT_ACCOUNT_PER_MINUTE": "1000001"}, nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := loadSessionManagement(func(k string) (string, bool) { v, ok := tc.env[k]; return v, ok }, tc.user)
			if (e != nil) != tc.fail || (c != nil) != tc.enabled {
				t.Fatalf("%+v %v", c, e)
			}
			if tc.enabled && *c != (SessionManagement{600, 120, 30, 4096}) {
				t.Fatal(c)
			}
		})
	}
}
