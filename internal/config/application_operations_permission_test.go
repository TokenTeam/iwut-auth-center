package config

import "testing"

func TestApplicationOperationsPermissionConfiguration(t *testing.T) {
	environment := map[string]string{}
	lookup := func(key string) (string, bool) { value, found := environment[key]; return value, found }
	configuration, err := loadApplicationOperationsPermission(lookup, nil, nil)
	if err != nil || configuration != nil {
		t.Fatal(configuration, err)
	}
	environment["AUTH_APPLICATION_OPERATIONS_PERMISSION_ENDPOINTS_ENABLED"] = "true"
	if _, err = loadApplicationOperationsPermission(lookup, nil, nil); err == nil {
		t.Fatal("missing user endpoint dependency")
	}
	if _, err = loadApplicationOperationsPermission(lookup, &UserEndpoints{}, nil); err == nil {
		t.Fatal("missing identity issuance dependency")
	}
	configuration, err = loadApplicationOperationsPermission(lookup, &UserEndpoints{}, &IdentityIssuance{})
	if err != nil || configuration.ReadPerMinute != 60 || configuration.WritePerMinute != 10 || configuration.MaxBuckets != 4096 || configuration.RecoveryReady {
		t.Fatal(configuration, err)
	}
	environment["AUTH_EMAIL_RECOVERY_READY"] = "true"
	environment["AUTH_EMAIL_LOGIN_ENABLED"] = "true"
	configuration, err = loadApplicationOperationsPermission(lookup, &UserEndpoints{}, &IdentityIssuance{})
	if err != nil || !configuration.RecoveryReady {
		t.Fatal(configuration, err)
	}
	environment["AUTH_APPLICATION_OPERATIONS_PERMISSION_MAX_BUCKETS"] = "0"
	if _, err = loadApplicationOperationsPermission(lookup, &UserEndpoints{}, &IdentityIssuance{}); err == nil {
		t.Fatal("unbounded buckets accepted")
	}
}
