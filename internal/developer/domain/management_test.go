package domain

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestDeveloperManagementTransitionsPreserveAccountAndRequireRecovery(t *testing.T) {
	now := time.Now()
	base := ManagedDeveloperState{AuthID: "u", AccountStatus: "DISABLED", Status: "APPROVED", Revision: 7}
	paused, e := ChangeDeveloperStatus(base, ManageDeveloperCommand{Action: "SUSPEND", ExpectedRevision: 7}, false, false, now)
	if e != nil || paused.Status != "SUSPENDED" || paused.AccountStatus != "DISABLED" || paused.Revision != 8 {
		t.Fatal(paused, e)
	}
	for _, readiness := range [][2]bool{{false, true}, {true, false}, {false, false}} {
		if _, e := ChangeDeveloperStatus(paused, ManageDeveloperCommand{Action: "RESTORE", ExpectedRevision: 8}, readiness[0], readiness[1], now); !errors.Is(e, ErrRestoreBlocked) {
			t.Fatal(e)
		}
	}
	restored, e := ChangeDeveloperStatus(paused, ManageDeveloperCommand{Action: "RESTORE", ExpectedRevision: 8}, true, true, now)
	if e != nil || restored.Status != "APPROVED" || restored.Revision != 9 || restored.AccountStatus != "DISABLED" {
		t.Fatal(restored, e)
	}
	for _, state := range []string{"APPROVED", "PENDING", "REJECTED", "WITHDRAWN"} {
		s := base
		s.Status = state
		if _, e := ChangeDeveloperStatus(s, ManageDeveloperCommand{Action: "RESTORE", ExpectedRevision: 7}, true, true, now); !errors.Is(e, ErrManagementConflict) {
			t.Fatal(state, e)
		}
	}
	base.Revision = math.MaxInt64
	if _, e := ChangeDeveloperStatus(base, ManageDeveloperCommand{Action: "SUSPEND", ExpectedRevision: math.MaxInt64}, true, true, now); !errors.Is(e, ErrDeveloperRevisionExhausted) {
		t.Fatal(e)
	}
}
