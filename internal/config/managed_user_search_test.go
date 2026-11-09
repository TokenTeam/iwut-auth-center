package config

import (
	"errors"
	"testing"
)

func TestManagedUserSearchOptIn(t *testing.T) {
	env := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if enabled, err := loadManagedUserSearch(lookup, nil, nil); enabled || err != nil {
		t.Fatal(enabled, err)
	}
	env[ManagedUserSearchEnabledEnv] = "true"
	if _, err := loadManagedUserSearch(lookup, &UserEndpoints{}, nil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal(err)
	}
	if enabled, err := loadManagedUserSearch(lookup, &UserEndpoints{}, &IdentityIssuance{}); !enabled || err != nil {
		t.Fatal(enabled, err)
	}
	env[ManagedUserSearchEnabledEnv] = "invalid"
	if _, err := loadManagedUserSearch(lookup, &UserEndpoints{}, &IdentityIssuance{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatal(err)
	}
}
