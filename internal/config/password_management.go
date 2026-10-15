package config

import (
	"fmt"
	"strconv"
)

func loadPasswordManagement(lookup LookupEnv, p *Password) (bool, error) {
	raw, ok := lookup("AUTH_PASSWORD_MANAGEMENT_ENABLED")
	if !ok {
		return false, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil || enabled && p == nil {
		return false, fmt.Errorf("%w: password management requires password runtime", ErrInvalidConfiguration)
	}
	return enabled, nil
}
