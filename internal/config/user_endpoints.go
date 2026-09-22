package config

import (
	"fmt"
	"strconv"
)

const UserEndpointsEnabledEnv = "AUTH_USER_ENDPOINTS_ENABLED"

type UserEndpoints struct {
	Authentication Authentication
	Association    Association
	Profile        ProfileConfig
	UserIdentity   UserIdentityConfig
}

func loadUserEndpoints(lookup LookupEnv) (*UserEndpoints, error) {
	raw, found := lookup(UserEndpointsEnabledEnv)
	if !found {
		return nil, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s must be a boolean", ErrInvalidConfiguration, UserEndpointsEnabledEnv)
	}
	if !enabled {
		return nil, nil
	}
	c := &UserEndpoints{}
	if c.Authentication, err = LoadAuthentication(lookup); err != nil {
		return nil, err
	}
	if c.Association, err = LoadAssociation(lookup); err != nil {
		return nil, err
	}
	if c.Profile, err = ParseProfileConfig(lookup); err != nil {
		return nil, err
	}
	if c.UserIdentity, err = ParseUserIdentityConfig(lookup); err != nil {
		return nil, err
	}
	return c, nil
}
