package config

import (
	"fmt"
	"strconv"
)

type ApplicationClosure struct {
	Enabled      bool
	AppServiceID string
}

type ApplicationCloseReauth struct {
	Enabled                                                        bool
	GlobalPerMinute, SourcePerMinute, AccountPerMinute, MaxBuckets int
}

func loadApplicationClosure(lookup LookupEnv, callers []ServiceCallerRegistration) (*ApplicationClosure, error) {
	raw, ok := lookup("AUTH_APPLICATION_CLOSURE_ENABLED")
	if !ok {
		return nil, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid AUTH_APPLICATION_CLOSURE_ENABLED", ErrInvalidConfiguration)
	}
	if !enabled {
		return nil, nil
	}
	appID := "iwut-app-center"
	if raw, ok = lookup("AUTH_APPLICATION_CLOSURE_APP_SERVICE_ID"); ok {
		appID = raw
	}
	foundApply, foundRead := false, false
	for _, caller := range callers {
		if caller.ServiceID != appID || caller.Status != "ACTIVE" {
			continue
		}
		for _, permission := range caller.Permissions {
			foundApply = foundApply || permission == "auth.application-closure.apply"
			foundRead = foundRead || permission == "auth.application-closure.read"
		}
	}
	if appID == "" || !foundApply || !foundRead {
		return nil, fmt.Errorf("%w: Application closure App caller is not authorized", ErrInvalidConfiguration)
	}
	return &ApplicationClosure{Enabled: true, AppServiceID: appID}, nil
}

func loadApplicationCloseReauth(lookup LookupEnv, users *UserEndpoints, issuance *IdentityIssuance) (*ApplicationCloseReauth, error) {
	raw, ok := lookup("AUTH_APPLICATION_CLOSE_REAUTH_ENABLED")
	if !ok {
		return nil, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid AUTH_APPLICATION_CLOSE_REAUTH_ENABLED", ErrInvalidConfiguration)
	}
	if !enabled {
		return nil, nil
	}
	if users == nil || issuance == nil {
		return nil, fmt.Errorf("%w: Application close reauthentication requires user endpoints and identity signing key", ErrInvalidConfiguration)
	}
	c := &ApplicationCloseReauth{Enabled: true, GlobalPerMinute: 600, SourcePerMinute: 120, AccountPerMinute: 10, MaxBuckets: 4096}
	for key, dst := range map[string]*int{
		"AUTH_APPLICATION_CLOSE_REAUTH_GLOBAL_PER_MINUTE":  &c.GlobalPerMinute,
		"AUTH_APPLICATION_CLOSE_REAUTH_SOURCE_PER_MINUTE":  &c.SourcePerMinute,
		"AUTH_APPLICATION_CLOSE_REAUTH_ACCOUNT_PER_MINUTE": &c.AccountPerMinute,
		"AUTH_APPLICATION_CLOSE_REAUTH_MAX_BUCKETS":        &c.MaxBuckets,
	} {
		if raw, ok := lookup(key); ok {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 || value > 1000000 {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, key)
			}
			*dst = value
		}
	}
	return c, nil
}
