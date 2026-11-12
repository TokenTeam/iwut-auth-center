package config

import (
	"fmt"
	"strconv"
)

const ScriptPermissionEnabledEnv = "AUTH_SCRIPT_PERMISSION_ENDPOINTS_ENABLED"

type ScriptPermission struct {
	RecoveryReady bool
}

func loadScriptPermission(lookup LookupEnv, user *UserEndpoints, issuance *IdentityIssuance) (*ScriptPermission, error) {
	raw, present := lookup(ScriptPermissionEnabledEnv)
	if !present {
		return nil, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, ScriptPermissionEnabledEnv)
	}
	if !enabled {
		return nil, nil
	}
	if user == nil || issuance == nil {
		return nil, fmt.Errorf("%w: script permission endpoints require user endpoints and identity issuance", ErrInvalidConfiguration)
	}
	configuration := &ScriptPermission{}
	if raw, present := lookup("AUTH_EMAIL_RECOVERY_READY"); present {
		ready, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid AUTH_EMAIL_RECOVERY_READY", ErrInvalidConfiguration)
		}
		configuration.RecoveryReady = ready
	}
	return configuration, nil
}
