package config

import (
	"fmt"
	"strconv"
)

type AccountManagement struct{ ReadPerMinute, WritePerMinute, MaxBuckets int }

func loadAccountManagement(lookup LookupEnv, user *UserEndpoints) (*AccountManagement, error) {
	raw, found := lookup("AUTH_ACCOUNT_MANAGEMENT_ENDPOINTS_ENABLED")
	if !found {
		return nil, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil || enabled && user == nil {
		return nil, fmt.Errorf("%w: account management requires valid flag and user endpoints", ErrInvalidConfiguration)
	}
	if !enabled {
		return nil, nil
	}
	c := &AccountManagement{60, 10, 4096}
	for name, dst := range map[string]*int{"AUTH_ACCOUNT_MANAGEMENT_READ_PER_MINUTE": &c.ReadPerMinute, "AUTH_ACCOUNT_MANAGEMENT_WRITE_PER_MINUTE": &c.WritePerMinute, "AUTH_ACCOUNT_MANAGEMENT_MAX_BUCKETS": &c.MaxBuckets} {
		if raw, ok := lookup(name); ok {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 1000000 {
				return nil, ErrInvalidConfiguration
			}
			*dst = n
		}
	}
	return c, nil
}
