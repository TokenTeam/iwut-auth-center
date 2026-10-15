package config

import "testing"

func TestPasswordLoginExplicitGate(t *testing.T) {
	values := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := values[k]; return v, ok }
	if enabled, err := loadPasswordLogin(lookup, nil, false); enabled || err != nil {
		t.Fatal(enabled, err)
	}
	for _, v := range []string{"true", "invalid"} {
		values["AUTH_PASSWORD_LOGIN_ENABLED"] = v
		if _, err := loadPasswordLogin(lookup, &Password{}, false); err == nil {
			t.Fatal("missing management accepted")
		}
	}
	values["AUTH_PASSWORD_LOGIN_ENABLED"] = "true"
	if _, err := loadPasswordLogin(lookup, nil, true); err == nil {
		t.Fatal("missing password accepted")
	}
	if enabled, err := loadPasswordLogin(lookup, &Password{}, true); !enabled || err != nil {
		t.Fatal(enabled, err)
	}
}
