package domain

import (
	"errors"
	"reflect"
	"testing"
)

func TestIndependentApplicationOperationPermissions(t *testing.T) {
	snapshot := Snapshot{AuthID: "user", AccountStatus: "ACTIVE", Permissions: []string{"app.profile.review", Suspend}, Revision: 4, EmailVerified: true, RecoveryReady: true}
	state, err := snapshot.State()
	if err != nil || !state.Has(Suspend) || state.Has(Restore) || !state.Permissions[1].Effective {
		t.Fatal(state, err)
	}
	grant, err := Change(snapshot, Command{Permission: Restore, Action: "GRANT", ExpectedRevision: 4})
	if err != nil || !reflect.DeepEqual(grant.Permissions, []string{"app.application.restore", "app.application.suspend", "app.profile.review"}) || grant.Revision != 5 {
		t.Fatal(grant, err)
	}
	revoked, err := Change(grant, Command{Permission: Suspend, Action: "REVOKE", ExpectedRevision: 5})
	if err != nil || !reflect.DeepEqual(revoked.Permissions, []string{"app.application.restore", "app.profile.review"}) {
		t.Fatal(revoked, err)
	}
}

func TestApplicationOperationGrantBlockersAndDisabledRevoke(t *testing.T) {
	snapshot := Snapshot{AuthID: "user", AccountStatus: "DISABLED", Permissions: []string{Suspend}, Revision: 1}
	state, err := snapshot.State()
	if err != nil || state.Permissions[1].Effective || !reflect.DeepEqual(state.GrantBlockers, []string{"ACCOUNT_DISABLED", "EMAIL_REQUIRED", "EMAIL_RECOVERY_UNAVAILABLE"}) {
		t.Fatal(state, err)
	}
	if _, err = Change(snapshot, Command{Permission: Restore, Action: "GRANT", ExpectedRevision: 1}); !errors.Is(err, ErrGrantBlocked) {
		t.Fatal(err)
	}
	if _, err = Change(snapshot, Command{Permission: Suspend, Action: "REVOKE", ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
}
