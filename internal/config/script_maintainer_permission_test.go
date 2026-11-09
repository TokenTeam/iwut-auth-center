package config

import (
	"errors"
	"testing"
)

func TestScriptMaintainerPermissionIndependentOptIn(t *testing.T) {
	env := map[string]string{"AUTH_APPLICATION_OPERATIONS_PERMISSION_ENDPOINTS_ENABLED": "true"}
	lookup := func(key string) (string, bool) { value, ok := env[key]; return value, ok }
	if got, err := loadScriptMaintainerPermission(lookup, nil, nil); got != nil || err != nil {
		t.Fatal(got, err)
	}
	env[ScriptMaintainerPermissionEnabledEnv] = "true"
	if _, err := loadScriptMaintainerPermission(lookup, &UserEndpoints{}, nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("missing issuance accepted", err)
	}
	if got, err := loadScriptMaintainerPermission(lookup, &UserEndpoints{}, &IdentityIssuance{}); err != nil || got == nil || !got.LegacyEnabled || got.Enabled || got.RecoveryReady {
		t.Fatal(got, err)
	}
	env["AUTH_EMAIL_RECOVERY_READY"] = "true"
	if got, err := loadScriptMaintainerPermission(lookup, &UserEndpoints{}, &IdentityIssuance{}); err != nil || got == nil || !got.RecoveryReady {
		t.Fatal(got, err)
	}
	delete(env, ScriptMaintainerPermissionEnabledEnv)
	env[ScriptPermissionEnabledEnv] = "true"
	if _, err := loadScriptMaintainerPermission(lookup, &UserEndpoints{}, nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal("missing issuance accepted", err)
	}
	if got, err := loadScriptMaintainerPermission(lookup, &UserEndpoints{}, &IdentityIssuance{}); err != nil || got == nil || got.LegacyEnabled || !got.Enabled || !got.RecoveryReady {
		t.Fatal(got, err)
	}
	env[ScriptPermissionEnabledEnv] = "invalid"
	if _, err := loadScriptMaintainerPermission(lookup, &UserEndpoints{}, &IdentityIssuance{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal(err)
	}
}
