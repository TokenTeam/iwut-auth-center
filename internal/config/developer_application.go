package config

import (
	"fmt"
	"strconv"
)

type DeveloperApplication struct {
	RecoveryReady                                                  bool
	GlobalPerMinute, SourcePerMinute, AccountPerMinute, MaxBuckets int
}

func loadDeveloperApplication(lookup LookupEnv, user *UserEndpoints) (*DeveloperApplication, error) {
	enabled, ready := false, false
	for key, dest := range map[string]*bool{"AUTH_DEVELOPER_APPLICATION_ENABLED": &enabled, "AUTH_EMAIL_RECOVERY_READY": &ready} {
		if raw, found := lookup(key); found {
			v, e := strconv.ParseBool(raw)
			if e != nil {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, key)
			}
			*dest = v
		}
	}
	c := &DeveloperApplication{RecoveryReady: ready, GlobalPerMinute: 600, SourcePerMinute: 120, AccountPerMinute: 30, MaxBuckets: 4096}
	for key, dest := range map[string]*int{"AUTH_DEVELOPER_GLOBAL_PER_MINUTE": &c.GlobalPerMinute, "AUTH_DEVELOPER_SOURCE_PER_MINUTE": &c.SourcePerMinute, "AUTH_DEVELOPER_ACCOUNT_PER_MINUTE": &c.AccountPerMinute, "AUTH_DEVELOPER_MAX_BUCKETS": &c.MaxBuckets} {
		if raw, found := lookup(key); found {
			v, e := strconv.Atoi(raw)
			if e != nil || v <= 0 || v > 1000000 {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, key)
			}
			*dest = v
		}
	}
	if !enabled {
		return nil, nil
	}
	if user == nil {
		return nil, fmt.Errorf("%w: developer application requires user endpoints", ErrInvalidConfiguration)
	}
	return c, nil
}
