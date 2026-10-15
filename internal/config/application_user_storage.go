package config

import (
	"fmt"
	"strings"
)

const ApplicationUserStorageEnabledEnv = "AUTH_APPLICATION_USER_STORAGE_ENABLED"

type ApplicationUserStorage struct {
	Enabled bool
}

func loadApplicationUserStorage(lookup LookupEnv, oauth *OAuth, users *UserEndpoints) (*ApplicationUserStorage, error) {
	raw, found := lookup(ApplicationUserStorageEnabledEnv)
	if !found || strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "false" {
		return nil, nil
	}
	if strings.TrimSpace(raw) != "true" || oauth == nil || !oauth.ResourceScopesReady || users == nil {
		return nil, fmt.Errorf("%w: %s requires resource-ready OAuth and user endpoints", ErrInvalidConfiguration, ApplicationUserStorageEnabledEnv)
	}
	return &ApplicationUserStorage{Enabled: true}, nil
}
