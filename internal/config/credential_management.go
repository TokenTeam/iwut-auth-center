package config

import (
	"fmt"
	"strings"
)

type CredentialManagement = SessionManagement

func loadCredentialManagement(lookup LookupEnv, user *UserEndpoints, password *Password) (*CredentialManagement, error) {
	c, err := loadSessionManagement(func(key string) (string, bool) {
		return lookup(strings.Replace(key, "AUTH_SESSION_MANAGEMENT_", "AUTH_CREDENTIAL_MANAGEMENT_", 1))
	}, user)
	if err != nil {
		return nil, err
	}
	if c != nil && password == nil {
		return nil, fmt.Errorf("%w: credential management requires password runtime", ErrInvalidConfiguration)
	}
	return c, nil
}
