package config

import "testing"

func TestDangerProofsRequirePasswordButRecoveryDoesNot(t *testing.T) {
	for _, account := range []*AccountClosure{nil, {Enabled: false}, {Enabled: true}} {
		for _, app := range []*ApplicationCloseReauth{nil, {Enabled: false}, {Enabled: true}} {
			enabled := account != nil && account.Enabled || app != nil && app.Enabled
			if err := validateDangerPasswordDependencies(nil, account, app); (err != nil) != enabled {
				t.Fatalf("gate mismatch: %v", err)
			}
			if err := validateDangerPasswordDependencies(&Password{}, account, app); err != nil {
				t.Fatal(err)
			}
		}
	}
}
