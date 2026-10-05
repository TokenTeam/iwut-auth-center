package config

import "testing"

func TestAccountClosureConfigurationSeparatesRuntimeAndPublicGate(t *testing.T) {
	lookup := func(values map[string]string) LookupEnv {
		return func(k string) (string, bool) { v, ok := values[k]; return v, ok }
	}
	if c, err := loadAccountClosure(lookup(nil), nil); err != nil || c != nil {
		t.Fatalf("default: %#v %v", c, err)
	}
	values := map[string]string{"AUTH_TERMINATION_LEDGER_DIR": "/var/lib/iwut-termination-ledger"}
	c, err := loadAccountClosure(lookup(values), &UserEndpoints{})
	if err != nil || c == nil || c.Enabled || c.ReadPerMinute != 30 || c.WritePerMinute != 10 {
		t.Fatalf("background-only runtime: %#v %v", c, err)
	}
	values["AUTH_ACCOUNT_CLOSURE_ENABLED"] = "true"
	if _, err = loadAccountClosure(lookup(values), &UserEndpoints{}); err == nil {
		t.Fatal("public closure accepted without policy readiness")
	}
	values["AUTH_CLOSURE_DATA_POLICY_READY"] = "true"
	if c, err = loadAccountClosure(lookup(values), &UserEndpoints{}); err != nil || !c.Enabled {
		t.Fatalf("ready deployment: %#v %v", c, err)
	}
	for key, bad := range map[string]string{"AUTH_TERMINATION_LEDGER_DIR": "relative", "AUTH_ACCOUNT_CLOSURE_ENABLED": "yes", "AUTH_ACCOUNT_CLOSURE_READ_PER_MINUTE": "0", "AUTH_ACCOUNT_CLOSURE_WORKER_INTERVAL": "0s"} {
		copy := map[string]string{}
		for k, v := range values {
			copy[k] = v
		}
		copy[key] = bad
		if _, err := loadAccountClosure(lookup(copy), &UserEndpoints{}); err == nil {
			t.Errorf("invalid %s accepted", key)
		}
	}
	if _, err = loadAccountClosure(lookup(values), nil); err == nil {
		t.Fatal("missing authentication runtime accepted")
	}
}
