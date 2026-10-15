package config

import (
	"fmt"
	"strconv"
)

func loadPasswordLogin(lookup LookupEnv, p *Password, management bool) (bool, error) {
	raw, ok := lookup("AUTH_PASSWORD_LOGIN_ENABLED")
	if !ok {
		return false, nil
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil || enabled && (p == nil || !management) {
		return false, fmt.Errorf("%w: password login requires password management runtime", ErrInvalidConfiguration)
	}
	return enabled, nil
}
