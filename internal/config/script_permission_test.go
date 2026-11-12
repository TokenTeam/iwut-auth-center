package config

import (
	"errors"
	"testing"
)

func TestScriptPermissionIndependentOptIn(t *testing.T) {
	env := map[string]string{"AUTH_APPLICATION_OPERATIONS_PERMISSION_ENDPOINTS_ENABLED": "true"}
	lookup := func(key string) (string, bool) { value, ok := env[key]; return value, ok }
	if got, err := loadScriptPermission(lookup, nil, nil); got != nil || err != nil {
		t.Fatal(got, err)
	}
	env["AUTH_SCRIPT_MAINTAINER_PERMISSION_ENDPOINTS_ENABLED"] = "true"
	if got, err := loadScriptPermission(lookup, nil, nil); got != nil || err != nil {
		t.Fatal("retired flag enabled the service", got, err)
	}
	env["AUTH_EMAIL_RECOVERY_READY"] = "true"
	env[ScriptPermissionEnabledEnv] = "true"
	if _, err := loadScriptPermission(lookup, &UserEndpoints{}, nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("missing issuance accepted", err)
	}
	if got, err := loadScriptPermission(lookup, &UserEndpoints{}, &IdentityIssuance{}); err != nil || got == nil || !got.RecoveryReady {
		t.Fatal(got, err)
	}
	env[ScriptPermissionEnabledEnv] = "invalid"
	if _, err := loadScriptPermission(lookup, &UserEndpoints{}, &IdentityIssuance{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal(err)
	}
}
