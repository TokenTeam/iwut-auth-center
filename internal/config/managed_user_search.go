package config

import (
	"fmt"
	"strconv"
)

const ManagedUserSearchEnabledEnv = "AUTH_MANAGED_USER_SEARCH_ENDPOINTS_ENABLED"

func loadManagedUserSearch(lookup LookupEnv, users *UserEndpoints, issuance *IdentityIssuance) (bool, error) {
	raw, present := lookup(ManagedUserSearchEnabledEnv)
	if !present {
		return false, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, ManagedUserSearchEnabledEnv)
	}
	if enabled && (users == nil || issuance == nil) {
		return false, fmt.Errorf("%w: managed user search requires user endpoints and identity issuance", ErrInvalidConfiguration)
	}
	return enabled, nil
}
