package config

import (
	"fmt"
	"strconv"
)

type ApplicationOperationsPermission struct {
	RecoveryReady                             bool
	ReadPerMinute, WritePerMinute, MaxBuckets int
}

func loadApplicationOperationsPermission(lookup LookupEnv, user *UserEndpoints, issuance *IdentityIssuance) (*ApplicationOperationsPermission, error) {
	configuration := &ApplicationOperationsPermission{ReadPerMinute: 60, WritePerMinute: 10, MaxBuckets: 4096}
	enabled, recoveryReady, emailLogin := false, false, false
	for name, target := range map[string]*bool{
		"AUTH_APPLICATION_OPERATIONS_PERMISSION_ENDPOINTS_ENABLED": &enabled,
		"AUTH_EMAIL_RECOVERY_READY":                                &recoveryReady,
		"AUTH_EMAIL_LOGIN_ENABLED":                                 &emailLogin,
	} {
		if raw, found := lookup(name); found {
			value, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, name)
			}
			*target = value
		}
	}
	configuration.RecoveryReady = recoveryReady && emailLogin
	for name, target := range map[string]*int{
		"AUTH_APPLICATION_OPERATIONS_PERMISSION_READ_PER_MINUTE":  &configuration.ReadPerMinute,
		"AUTH_APPLICATION_OPERATIONS_PERMISSION_WRITE_PER_MINUTE": &configuration.WritePerMinute,
		"AUTH_APPLICATION_OPERATIONS_PERMISSION_MAX_BUCKETS":      &configuration.MaxBuckets,
	} {
		if raw, found := lookup(name); found {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 || value > 1000000 {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, name)
			}
			*target = value
		}
	}
	if !enabled {
		return nil, nil
	}
	if user == nil || issuance == nil {
		return nil, fmt.Errorf("%w: application operations permission endpoints require user endpoints and identity issuance", ErrInvalidConfiguration)
	}
	return configuration, nil
}
