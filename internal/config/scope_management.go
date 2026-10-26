package config

import (
	"fmt"
	"strconv"
)

const ScopeManagementEnabledEnv = "AUTH_SCOPE_MANAGEMENT_ENABLED"

func loadScopeManagement(lookup LookupEnv, user *UserEndpoints, issuance *IdentityIssuance, oauth *OAuth) (bool, error) {
	raw, found := lookup(ScopeManagementEnabledEnv)
	if !found {
		return false, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, ScopeManagementEnabledEnv)
	}
	if enabled && (user == nil || issuance == nil || oauth == nil || oauth.CatalogFile == "") {
		return false, fmt.Errorf("%w: scope management requires user identity issuance and a persistent OAuth manifest", ErrInvalidConfiguration)
	}
	return enabled, nil
}
