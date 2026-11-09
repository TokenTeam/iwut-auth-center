package config

import (
	"fmt"
	"strconv"
)

const (
	ScriptMaintainerPermissionEnabledEnv = "AUTH_SCRIPT_MAINTAINER_PERMISSION_ENDPOINTS_ENABLED"
	ScriptPermissionEnabledEnv           = "AUTH_SCRIPT_PERMISSION_ENDPOINTS_ENABLED"
)

type ScriptMaintainerPermission struct {
	LegacyEnabled, Enabled, RecoveryReady bool
}

func loadScriptMaintainerPermission(lookup LookupEnv, user *UserEndpoints, issuance *IdentityIssuance) (*ScriptMaintainerPermission, error) {
	configuration := &ScriptMaintainerPermission{}
	for _, flag := range []struct {
		name    string
		enabled *bool
	}{
		{ScriptMaintainerPermissionEnabledEnv, &configuration.LegacyEnabled},
		{ScriptPermissionEnabledEnv, &configuration.Enabled},
	} {
		if raw, present := lookup(flag.name); present {
			enabled, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, flag.name)
			}
			*flag.enabled = enabled
		}
	}
	if !configuration.LegacyEnabled && !configuration.Enabled {
		return nil, nil
	}
	if user == nil || issuance == nil {
		return nil, fmt.Errorf("%w: script permission endpoints require user endpoints and identity issuance", ErrInvalidConfiguration)
	}
	if raw, present := lookup("AUTH_EMAIL_RECOVERY_READY"); present {
		ready, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid AUTH_EMAIL_RECOVERY_READY", ErrInvalidConfiguration)
		}
		configuration.RecoveryReady = ready
	}
	return configuration, nil
}
