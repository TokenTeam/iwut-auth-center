package config

import (
	"errors"
	"testing"
)

func TestLoadApplicationClosureRequiresExactActiveAppPermissions(t *testing.T) {
	lookup := func(key string) (string, bool) {
		if key == "AUTH_APPLICATION_CLOSURE_ENABLED" {
			return "true", true
		}
		return "", false
	}
	callers := []ServiceCallerRegistration{{ServiceID: "iwut-app-center", Status: "ACTIVE", Permissions: []string{"auth.application-closure.apply", "auth.application-closure.read"}}}
	configuration, err := loadApplicationClosure(lookup, callers)
	if err != nil || configuration == nil || configuration.AppServiceID != "iwut-app-center" {
		t.Fatalf("loadApplicationClosure() = %#v, %v", configuration, err)
	}
	for _, registration := range []ServiceCallerRegistration{
		{ServiceID: "iwut-app-center", Status: "DISABLED", Permissions: callers[0].Permissions},
		{ServiceID: "iwut-app-center", Status: "ACTIVE", Permissions: []string{"auth.application-closure.apply"}},
		{ServiceID: "other", Status: "ACTIVE", Permissions: callers[0].Permissions},
	} {
		if _, err = loadApplicationClosure(lookup, []ServiceCallerRegistration{registration}); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("registration %#v accepted: %v", registration, err)
		}
	}
}

func TestLoadApplicationCloseReauthDefaultsAndBounds(t *testing.T) {
	lookup := func(key string) (string, bool) {
		if key == "AUTH_APPLICATION_CLOSE_REAUTH_ENABLED" {
			return "true", true
		}
		return "", false
	}
	configuration, err := loadApplicationCloseReauth(lookup, &UserEndpoints{}, &IdentityIssuance{})
	if err != nil || configuration.AccountPerMinute != 10 || configuration.SourcePerMinute != 120 || configuration.GlobalPerMinute != 600 || configuration.MaxBuckets != 4096 {
		t.Fatalf("defaults = %#v, %v", configuration, err)
	}
	if _, err = loadApplicationCloseReauth(func(key string) (string, bool) {
		if key == "AUTH_APPLICATION_CLOSE_REAUTH_ENABLED" {
			return "true", true
		}
		if key == "AUTH_APPLICATION_CLOSE_REAUTH_ACCOUNT_PER_MINUTE" {
			return "0", true
		}
		return "", false
	}, &UserEndpoints{}, &IdentityIssuance{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("invalid limit accepted: %v", err)
	}
}
