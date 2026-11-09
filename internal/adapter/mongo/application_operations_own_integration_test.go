package mongo

import (
	"errors"
	"slices"
	"sync"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	account "iwut-auth-center/internal/account/domain"
	domain "iwut-auth-center/internal/applicationoperations/domain"
)

func TestApplicationOperationsOwnMongoFormalGrantsAndConcurrentSnapshot(t *testing.T) {
	r, subject := applicationOperationsFixture(t)
	actor := account.WithIdentity(t.Context(), "admin", 1)
	self := account.WithIdentity(t.Context(), subject, 1)
	start := make(chan struct{})
	reads := make(chan domain.OwnState, 8)
	failures := make(chan error, 9)
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			state, err := r.GetOwn(self, subject)
			if err != nil {
				failures <- err
				return
			}
			reads <- state
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		_, err := r.Manage(actor, domain.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: domain.Suspend, Action: "GRANT", ExpectedRevision: 1, Reason: "own read race"})
		if err != nil {
			failures <- err
		}
	}()
	close(start)
	workers.Wait()
	close(reads)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	for state := range reads {
		if state.Revision == 1 && len(state.EffectivePermissions) == 0 {
			continue
		}
		if state.Revision == 2 && slices.Equal(state.EffectivePermissions, []string{domain.Suspend}) {
			continue
		}
		t.Fatal("mixed permission snapshot", state)
	}
	for _, step := range []struct {
		permission, action string
		revision           int64
		want               []string
	}{
		{domain.Restore, "GRANT", 2, []string{domain.Restore, domain.Suspend}},
		{domain.Suspend, "REVOKE", 3, []string{domain.Restore}},
		{domain.Restore, "REVOKE", 4, []string{}},
	} {
		if _, err := r.Manage(actor, domain.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: step.permission, Action: step.action, ExpectedRevision: step.revision, Reason: "own permissions lifecycle"}); err != nil {
			t.Fatal(err)
		}
		state, err := r.GetOwn(self, subject)
		if err != nil || state.Revision != step.revision+1 || !slices.Equal(state.EffectivePermissions, step.want) {
			t.Fatal(state, err)
		}
	}
	if count, err := r.authentication.database.Collection(PermissionAuditCollection).CountDocuments(t.Context(), bson.M{"subjectAuthId": subject}); err != nil || count != 4 {
		t.Fatal("reads changed grant audit", count, err)
	}
}

func TestApplicationOperationsOwnMongoNoAdministratorEmailOrRecoveryGate(t *testing.T) {
	reviewer, db, _ := reviewerFixture(t, true) // no administrator initialization
	r, _ := NewApplicationOperationsPermissionRepository(reviewer.authentication, false)
	ctx := account.WithIdentity(t.Context(), "admin", 1) // ordinary USER, no email
	for i, permissions := range [][]string{{}, {domain.Suspend}, {domain.Restore}, {domain.Suspend, "app.profile.review", domain.Restore}} {
		revision := int64(i + 1)
		if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": "admin"}, bson.M{"$set": bson.M{"permissions": permissions, "permissionRevision": revision}}); err != nil {
			t.Fatal(err)
		}
		out, err := r.GetOwn(ctx, "admin")
		want, _ := domain.ProjectOwn("admin", revision, permissions)
		if err != nil || out.AuthID != "admin" || out.Revision != revision || !slices.Equal(out.EffectivePermissions, want.EffectivePermissions) || out.EffectivePermissions == nil {
			t.Fatal(out, err, want)
		}
		// The management repository intentionally fails unavailable without its
		// bootstrap marker. HTTP/gRPC reject this ordinary actor earlier (403).
		if _, err = r.Get(ctx, "admin", "admin"); !errors.Is(err, domain.ErrUnavailable) {
			t.Fatal("old target read lost its initialization gate", err)
		}
	}
	count, err := db.Collection(PermissionAuditCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil || count != 0 {
		t.Fatal("read created permission audit", count, err)
	}
}

func TestApplicationOperationsOwnMongoIdentityAndCorruptionFailClosed(t *testing.T) {
	reviewer, db, _ := reviewerFixture(t, true)
	r, _ := NewApplicationOperationsPermissionRepository(reviewer.authentication, false)
	ctx := account.WithIdentity(t.Context(), "admin", 1)
	for _, fields := range []bson.M{
		{"permissions": bson.A{domain.Suspend, domain.Suspend}},
		{"permissions": bson.A{domain.Suspend, 1}},
		{"permissions": bson.A{domain.Suspend, "bad permission"}},
		{"permissionRevision": int64(0)}, {"permissionRevision": int32(1)},
		{"accountRevision": int32(1)}, {"accountStatus": "BROKEN"},
	} {
		base := bson.M{"permissions": bson.A{}, "permissionRevision": int64(1), "accountRevision": int64(1), "accountStatus": "ACTIVE"}
		for key, value := range fields {
			base[key] = value
		}
		if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": "admin"}, bson.M{"$set": base}); err != nil {
			t.Fatal(err)
		}
		if out, err := r.GetOwn(ctx, "admin"); !errors.Is(err, domain.ErrUnavailable) || out.AuthID != "" {
			t.Fatal(fields, out, err)
		}
	}
	if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": "admin"}, bson.M{"$set": bson.M{"permissions": bson.A{}, "permissionRevision": int64(1), "accountRevision": int64(2), "accountStatus": "ACTIVE"}}); err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct {
		actor    string
		revision int64
	}{{"admin", 1}, {"missing", 1}, {"admin", 0}} {
		if out, err := r.GetOwn(account.WithIdentity(t.Context(), call.actor, call.revision), call.actor); !errors.Is(err, domain.ErrIdentity) || out.AuthID != "" {
			t.Fatal(out, err)
		}
	}
	if _, err := r.GetOwn(ctx, "other"); !errors.Is(err, domain.ErrIdentity) {
		t.Fatal(err)
	}
	if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": "admin"}, bson.M{"$set": bson.M{"accountStatus": "DISABLED"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetOwn(account.WithIdentity(t.Context(), "admin", 2), "admin"); !errors.Is(err, domain.ErrIdentity) {
		t.Fatal(err)
	}
}
