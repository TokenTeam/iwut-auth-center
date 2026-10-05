package config

import (
	"fmt"
	"strconv"
)

type PlatformAdministrator struct {
	RecoveryReady                             bool
	ReadPerMinute, WritePerMinute, MaxBuckets int
}

func loadPlatformAdministrator(lookup LookupEnv, user *UserEndpoints) (*PlatformAdministrator, error) {
	c := &PlatformAdministrator{ReadPerMinute: 60, WritePerMinute: 10, MaxBuckets: 4096}
	enabled, ready, login := false, false, false
	for k, d := range map[string]*bool{"AUTH_PLATFORM_ADMIN_ENDPOINTS_ENABLED": &enabled, "AUTH_EMAIL_RECOVERY_READY": &ready, "AUTH_EMAIL_LOGIN_ENABLED": &login} {
		if raw, ok := lookup(k); ok {
			v, e := strconv.ParseBool(raw)
			if e != nil {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, k)
			}
			*d = v
		}
	}
	c.RecoveryReady = ready && login
	for k, d := range map[string]*int{"AUTH_PLATFORM_ADMIN_READ_PER_MINUTE": &c.ReadPerMinute, "AUTH_PLATFORM_ADMIN_WRITE_PER_MINUTE": &c.WritePerMinute, "AUTH_PLATFORM_ADMIN_MAX_BUCKETS": &c.MaxBuckets} {
		if raw, ok := lookup(k); ok {
			v, e := strconv.Atoi(raw)
			if e != nil || v < 1 || v > 1000000 {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, k)
			}
			*d = v
		}
	}
	if !enabled {
		return nil, nil
	}
	if user == nil {
		return nil, fmt.Errorf("%w: platform administrator requires user endpoints", ErrInvalidConfiguration)
	}
	return c, nil
}
