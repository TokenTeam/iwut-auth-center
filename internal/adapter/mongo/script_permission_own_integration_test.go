package mongo

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	account "iwut-auth-center/internal/account/domain"
	d "iwut-auth-center/internal/scriptmaintainer/domain"
)

func TestScriptOwnMongoBeforeBootstrapWithoutRecoveryAndFailure(t *testing.T) {
	fixture, db, subject := reviewerFixture(t, true)
	repo := NewScriptMaintainerPermissionRepository(fixture.authentication, false)
	self := account.WithIdentity(t.Context(), subject, 1)
	// Remove the email directory completely. Own discovery must not read it.
	if _, err := db.Collection(EmailDirectoryCollection).DeleteOne(t.Context(), bson.M{"authId": subject}); err != nil {
		t.Fatal(err)
	}
	state, err := repo.GetOwn(self, subject)
	if err != nil || state.AuthID != subject || state.Revision != 1 || len(state.Permissions) != 5 {
		t.Fatal(state, err)
	}
	for _, item := range state.Permissions {
		if item.Granted || item.Effective {
			t.Fatal(state)
		}
	}
	for _, query := range []struct {
		actor    string
		revision int64
	}{
		{"missing", 1}, {subject, 2},
	} {
		if _, err := repo.GetOwn(account.WithIdentity(t.Context(), query.actor, query.revision), query.actor); !errors.Is(err, d.ErrIdentity) {
			t.Fatal(query, err)
		}
	}
	for _, status := range []string{"DISABLED", "ACTIVE"} {
		revision := int64(1)
		if status == "ACTIVE" {
			revision = 2
		}
		if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": subject}, bson.M{"$set": bson.M{"accountStatus": status, "accountRevision": revision}}); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.GetOwn(self, subject); !errors.Is(err, d.ErrIdentity) {
			t.Fatal("disabled or old generation accepted", status, err)
		}
	}
	fresh := account.WithIdentity(t.Context(), subject, 2)
	if _, err := repo.GetOwn(fresh, subject); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []bson.M{
		{"permissionRevision": int64(0)}, {"permissionRevision": "bad"}, {"permissions": bson.A{d.ReviewPermission, d.ReviewPermission}},
	} {
		if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": subject}, bson.M{"$set": bad}); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.GetOwn(fresh, subject); !errors.Is(err, d.ErrUnavailable) {
			t.Fatal(bad, err)
		}
		if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": subject}, bson.M{"$set": bson.M{"permissionRevision": int64(1), "permissions": bson.A{}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Collection(PrincipalCollection).ReplaceOne(t.Context(), bson.M{"authId": subject}, bson.M{"authId": subject, "principalType": "USER", "accountStatus": "CLOSED", "accountRevision": int64(3), "terminatedAt": time.Now().UTC(), "closureOperationId": uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetOwn(fresh, subject); !errors.Is(err, d.ErrIdentity) {
		t.Fatal(err)
	}
	if err := BootstrapSystemPrincipals(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	var system bson.M
	if err := db.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"principalType": "SYSTEM"}).Decode(&system); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetOwn(account.WithIdentity(t.Context(), system["authId"].(string), 1), system["authId"].(string)); !errors.Is(err, d.ErrIdentity) {
		t.Fatal(err)
	}
}

func TestScriptOwnMongoConcurrentGrantAndSnapshot(t *testing.T) {
	fixture, db, subject := reviewerFixture(t)
	adminVerifiedEmail(t, db, subject)
	repo := NewScriptMaintainerPermissionRepository(fixture.authentication, true)
	self := account.WithIdentity(t.Context(), subject, 1)
	actor := account.WithIdentity(t.Context(), "admin", 1)
	start := make(chan struct{})
	results := make(chan d.State, 8)
	failures := make(chan error, 9)
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			state, err := repo.GetOwn(self, subject)
			if err != nil {
				failures <- err
			} else {
				results <- state
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		_, err := repo.Manage(actor, d.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: d.ReviewPermission, Action: "GRANT", ExpectedRevision: 1, Reason: "own read race"})
		if err != nil {
			failures <- err
		}
	}()
	close(start)
	workers.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	for state := range results {
		item := state.For(d.ReviewPermission)
		if (state.Revision == 1 && !item.Granted && !item.Effective) || (state.Revision == 2 && item.Granted && item.Effective) {
			continue
		}
		t.Fatal("mixed own snapshot", state)
	}
	if _, err := repo.Manage(actor, d.Command{ActorAuthID: "admin", SubjectAuthID: subject, Permission: d.ReviewPermission, Action: "REVOKE", ExpectedRevision: 2, Reason: "end duty"}); err != nil {
		t.Fatal(err)
	}
	state, err := repo.GetOwn(self, subject)
	if err != nil || state.Revision != 3 || state.For(d.ReviewPermission).Granted {
		t.Fatal(state, err)
	}
	count, err := db.Collection(PermissionAuditCollection).CountDocuments(t.Context(), bson.M{"subjectAuthId": subject})
	if err != nil || count != 2 {
		t.Fatal("own reads altered permission audit", count, err)
	}
	if _, err := repo.Get(self, subject, subject); !errors.Is(err, d.ErrForbidden) {
		t.Fatal("own-read relaxed target Get", err)
	}
	cancelled, cancel := context.WithCancel(self)
	cancel()
	if _, err := repo.GetOwn(cancelled, subject); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
