package domain

import "testing"

func TestBR_DEV_003_LifecycleProjection(t *testing.T) {
	for _, tc := range []struct {
		account   AccountStatus
		developer DeveloperStatus
		ok        bool
	}{{AccountActive, DeveloperStatusWithdrawn, true}, {AccountDisabled, DeveloperStatusApproved, true}, {AccountClosed, "", true}, {AccountClosed, DeveloperStatusApproved, false}, {"", DeveloperStatusApproved, false}, {"UNKNOWN", DeveloperStatusApproved, false}} {
		_, err := NewPrincipalWithAccountStatus("user", PrincipalTypeUser, tc.developer, tc.account)
		if (err == nil) != tc.ok {
			t.Fatalf("%v: %v", tc, err)
		}
	}
}
