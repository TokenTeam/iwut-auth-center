package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnerExitDeploymentGate(t *testing.T) {
	env := map[string]string{}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if c, e := loadOwnerExit(lookup, nil, nil); e != nil || c != nil {
		t.Fatal(c, e)
	}
	env["AUTH_DEVELOPER_WITHDRAWAL_ENABLED"] = "true"
	if _, e := loadOwnerExit(lookup, &UserEndpoints{}, nil); e == nil {
		t.Fatal("enabled without App config")
	}
	p := filepath.Join(t.TempDir(), "owner.json")
	env["AUTH_OWNER_EXIT_CONFIG_FILE"] = p
	_ = os.WriteFile(p, []byte(`{"appTarget":"127.0.0.1:9000","appPlaintextLoopback":true,"serviceKeyId":"service","serviceKeyFile":"key.pem"}`), 0600)
	if _, e := loadOwnerExit(lookup, &UserEndpoints{}, nil); e == nil {
		t.Fatal("missing trusted recovery caller")
	}
	callers := []ServiceCallerRegistration{{ServiceID: "app-center", Status: "ACTIVE", Permissions: []string{"auth.account-owner-exit.read"}}}
	c, e := loadOwnerExit(lookup, &UserEndpoints{}, callers)
	if e != nil || !c.WithdrawalEnabled || c.ReadPerMinute != 60 || c.WritePerMinute != 10 {
		t.Fatal(c, e)
	}
	env["AUTH_DEVELOPER_WITHDRAWAL_ENABLED"] = "false"
	if c, e = loadOwnerExit(lookup, &UserEndpoints{}, callers); e != nil || c == nil || c.WithdrawalEnabled {
		t.Fatal("recovery runtime must survive public gate", c, e)
	}
}
