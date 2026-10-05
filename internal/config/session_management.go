package config

import (
	"fmt"
	"strconv"
)

type SessionManagement struct{ GlobalPerMinute, SourcePerMinute, AccountPerMinute, MaxBuckets int }

func loadSessionManagement(lookup LookupEnv, user *UserEndpoints) (*SessionManagement, error) {
	enabled := false
	if raw, ok := lookup("AUTH_SESSION_MANAGEMENT_ENABLED"); ok {
		var err error
		enabled, err = strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid AUTH_SESSION_MANAGEMENT_ENABLED", ErrInvalidConfiguration)
		}
	}
	c := &SessionManagement{600, 120, 30, 4096}
	for key, dst := range map[string]*int{"AUTH_SESSION_MANAGEMENT_GLOBAL_PER_MINUTE": &c.GlobalPerMinute, "AUTH_SESSION_MANAGEMENT_SOURCE_PER_MINUTE": &c.SourcePerMinute, "AUTH_SESSION_MANAGEMENT_ACCOUNT_PER_MINUTE": &c.AccountPerMinute, "AUTH_SESSION_MANAGEMENT_MAX_BUCKETS": &c.MaxBuckets} {
		if raw, ok := lookup(key); ok {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 1000000 {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, key)
			}
			*dst = n
		}
	}
	if !enabled {
		return nil, nil
	}
	if user == nil {
		return nil, fmt.Errorf("%w: Session management requires user endpoints", ErrInvalidConfiguration)
	}
	return c, nil
}
