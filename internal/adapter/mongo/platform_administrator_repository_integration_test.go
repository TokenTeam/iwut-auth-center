package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	account "iwut-auth-center/internal/account/domain"
	d "iwut-auth-center/internal/administrator/domain"
	review "iwut-auth-center/internal/reviewer/domain"
	"sync"
	"testing"
	"time"
)

func adminVerifiedEmail(t *testing.T, db *m.Database, id string) {
	t.Helper()
	if err := EnsureEmailAccountSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	bindingID := uuid.NewString()
	var prior emailDirectoryDocument
	if err := db.Collection(EmailDirectoryCollection).FindOne(t.Context(), bson.M{"authId": id}).Decode(&prior); err == nil {
		bindingID = prior.LoginBindingID
	}
	if _, err := db.Collection(EmailBindingCollection).UpdateOne(t.Context(), bson.M{"bindingId": bindingID}, bson.M{"$set": emailBindingDocument{BindingID: bindingID, AuthID: id, Email: id + "@example.test", VerifiedAt: time.Now().UTC().Truncate(time.Millisecond)}}, options.UpdateOne().SetUpsert(true)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection(EmailDirectoryCollection).UpdateOne(t.Context(), bson.M{"authId": id}, bson.M{"$setOnInsert": emailDirectoryDocument{AuthID: id, LoginBindingID: bindingID, Revision: 1, LoginRoleRevision: 1, VerifiedCount: 1}}, options.UpdateOne().SetUpsert(true)); err != nil {
		t.Fatal(err)
	}

}
func seedAdministrator(t *testing.T, a *AuthenticationRepository, id string) {
	t.Helper()
	if e := EnsurePlatformAdministratorSchema(t.Context(), a.database); e != nil {
		t.Fatal(e)
	}
	adminVerifiedEmail(t, a.database, id)
	r, _ := NewPlatformAdministratorRepository(a, true)
	result, e := r.Bootstrap(t.Context(), id)
	if e != nil || !result.Applied {
		t.Fatal(result, e)
	}
}
func administratorFixture(t *testing.T) (*PlatformAdministratorRepository, *m.Database, string) {
	t.Helper()
	a, db, s, _ := sessionRevocationFixture(t)
	_, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"permissions": bson.A{}, "permissionRevision": int64(1)}})
	if e != nil {
		t.Fatal(e)
	}
	seedAdministrator(t, a, s.AuthID)
	r, _ := NewPlatformAdministratorRepository(a, true)
	return r, db, s.AuthID
}
func adminCandidate(t *testing.T, db *m.Database, id string) {
	t.Helper()
	_, e := db.Collection(PrincipalCollection).InsertOne(t.Context(), bson.M{"authId": id, "principalType": "USER", "accountStatus": "ACTIVE", "accountRevision": int64(1), "minimumCredentialRevision": int64(1), "permissions": bson.A{"app.profile.review", "app.version.review"}, "permissionRevision": int64(1)})
	if e != nil {
		t.Fatal(e)
	}
	adminVerifiedEmail(t, db, id)
}
func TestPlatformAdministratorMongoLastProtectionAndConcurrentSelfRevoke(t *testing.T) {
	r, db, actor := administratorFixture(t)
	if _, e := r.Manage(account.WithIdentity(t.Context(), actor, 1), d.Command{ActorAuthID: actor, SubjectAuthID: actor, Action: "REVOKE", Reason: "test", ExpectedRevision: 2}); !errors.Is(e, d.ErrLast) {
		t.Fatal(e)
	}
	adminCandidate(t, db, "second")
	if _, e := r.Manage(account.WithIdentity(t.Context(), actor, 1), d.Command{ActorAuthID: actor, SubjectAuthID: "second", Action: "GRANT", Reason: "test", ExpectedRevision: 1}); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []string{actor, "second"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := r.Manage(account.WithIdentity(t.Context(), id, 1), d.Command{ActorAuthID: id, SubjectAuthID: id, Action: "REVOKE", Reason: "self revoke", ExpectedRevision: 2})
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else if !errors.Is(e, d.ErrLast) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	count, e := db.Collection(PrincipalCollection).CountDocuments(t.Context(), bson.M{"permissions": bson.M{"$all": d.Permissions()}})
	if e != nil || count != 1 {
		t.Fatal(count, e)
	}
	var second bson.Raw
	if e = db.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": "second"}).Decode(&second); e != nil {
		t.Fatal(e)
	}
	ps, _ := adminPermissions(second.Lookup("permissions"))
	for _, p := range []string{"app.profile.review", "app.version.review"} {
		found := false
		for _, x := range ps {
			if x == p {
				found = true
			}
		}
		if !found {
			t.Fatal(ps)
		}
	}
}
func TestPlatformAdministratorMongoReadinessCASPaginationAndRevokedActor(t *testing.T) {
	r, db, actor := administratorFixture(t)
	adminCandidate(t, db, "zz-b")
	adminCandidate(t, db, "zz-c")
	_, e := db.Collection(EmailBindingCollection).DeleteOne(t.Context(), bson.M{"authId": "zz-b"})
	if e != nil {
		t.Fatal(e)
	}
	c := d.Command{ActorAuthID: actor, SubjectAuthID: "zz-b", Action: "GRANT", Reason: "test", ExpectedRevision: 1}
	if _, e = r.Manage(account.WithIdentity(t.Context(), actor, 1), c); !errors.Is(e, d.ErrUnavailable) {
		t.Fatal(e)
	}
	c.ExpectedRevision = 2
	adminVerifiedEmail(t, db, "zz-b")
	if _, e = r.Manage(account.WithIdentity(t.Context(), actor, 1), c); !errors.Is(e, d.ErrConflict) {
		t.Fatal(e)
	}
	c.ExpectedRevision = 1
	adminVerifiedEmail(t, db, "zz-b")
	r.recoveryReady = false
	if _, e = r.Manage(account.WithIdentity(t.Context(), actor, 1), c); !errors.Is(e, d.ErrGrantBlocked) {
		t.Fatal(e)
	}
	r.recoveryReady = true
	for _, id := range []string{"zz-b", "zz-c"} {
		c.SubjectAuthID = id
		if _, e = r.Manage(account.WithIdentity(t.Context(), actor, 1), c); e != nil {
			t.Fatal(e)
		}
	}
	page, e := r.List(account.WithIdentity(t.Context(), actor, 1), actor, "zz-a", 1)
	if e != nil || len(page.Items) != 1 || page.Items[0].AuthID != "zz-b" || page.NextAfterAuthID != "zz-b" {
		t.Fatal(page, e)
	}
	r.recoveryReady = false
	if _, e = r.Manage(account.WithIdentity(t.Context(), actor, 1), d.Command{ActorAuthID: actor, SubjectAuthID: "zz-b", Action: "REVOKE", Reason: "test", ExpectedRevision: 2}); e != nil {
		t.Fatal(e)
	}
	page, e = r.List(account.WithIdentity(t.Context(), actor, 1), actor, page.NextAfterAuthID, 1)
	if e != nil || len(page.Items) != 1 || page.Items[0].AuthID != "zz-c" || page.NextAfterAuthID != "" {
		t.Fatal(page, e)
	}
	if _, e = r.Get(account.WithIdentity(t.Context(), "zz-b", 1), "zz-b", actor); !errors.Is(e, d.ErrForbidden) {
		t.Fatal(e)
	}
	rr, _ := NewReviewerRepository(r.authentication)
	if _, e = rr.Get(account.WithIdentity(t.Context(), "zz-b", 1), "zz-b", actor); !errors.Is(e, review.ErrForbidden) {
		t.Fatal(e)
	}
}
func TestPlatformAdministratorMongoPartialAndDisabledCannotProtectLast(t *testing.T) {
	r, db, actor := administratorFixture(t)
	adminCandidate(t, db, "other")
	_, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": "other"}, bson.M{"$set": bson.M{"permissions": d.Permissions(), "accountStatus": "DISABLED"}})
	if e != nil {
		t.Fatal(e)
	}
	c := d.Command{ActorAuthID: actor, SubjectAuthID: actor, Action: "REVOKE", Reason: "test", ExpectedRevision: 2}
	if _, e = r.Manage(account.WithIdentity(t.Context(), actor, 1), c); !errors.Is(e, d.ErrLast) {
		t.Fatal(e)
	}
	if _, e = r.Manage(account.WithIdentity(t.Context(), actor, 1), d.Command{ActorAuthID: actor, SubjectAuthID: "other", Action: "REVOKE", Reason: "test", ExpectedRevision: 1}); e != nil {
		t.Fatal(e)
	}
	_, e = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": "other"}, bson.M{"$set": bson.M{"permissions": bson.A{"auth.reviewer.manage"}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Get(account.WithIdentity(t.Context(), actor, 1), actor, "other"); !errors.Is(e, d.ErrUnavailable) {
		t.Fatal(e)
	}
	if _, e = r.Get(account.WithIdentity(t.Context(), "other", 1), "other", actor); !errors.Is(e, d.ErrIdentity) {
		t.Fatal(e)
	}
}
func TestPlatformAdministratorMongoSharedReviewerCASAndAuditRollback(t *testing.T) {
	r, db, actor := administratorFixture(t)
	if e := EnsureReviewerSchema(t.Context(), db); e != nil {
		t.Fatal(e)
	}
	adminCandidate(t, db, "candidate")
	rr, _ := NewReviewerRepository(r.authentication)
	ch := make(chan error, 2)
	go func() {
		_, e := r.Manage(account.WithIdentity(t.Context(), actor, 1), d.Command{ActorAuthID: actor, SubjectAuthID: "candidate", Action: "GRANT", Reason: "test", ExpectedRevision: 1})
		ch <- e
	}()
	go func() {
		_, e := rr.Manage(account.WithIdentity(t.Context(), actor, 1), review.Command{ActorAuthID: actor, SubjectAuthID: "candidate", Permission: review.Reviewer, Action: "REVOKE", Reason: "test", ExpectedRevision: 1})
		ch <- e
	}()
	success := 0
	for range 2 {
		e := <-ch
		if e == nil {
			success++
		} else if !errors.Is(e, d.ErrConflict) && !errors.Is(e, review.ErrConflict) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	// A collection validator rejects the immutable audit after CAS; state must roll back.
	adminCandidate(t, db, "rollback")
	if e := db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: PlatformAdminAuditCollection}, {Key: "validator", Value: bson.M{"subjectAuthId": bson.M{"$ne": "rollback"}}}, {Key: "validationLevel", Value: "strict"}}).Err(); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Manage(account.WithIdentity(t.Context(), actor, 1), d.Command{ActorAuthID: actor, SubjectAuthID: "rollback", Action: "GRANT", Reason: "test", ExpectedRevision: 1}); !errors.Is(e, d.ErrUnavailable) {
		t.Fatal(e)
	}
	state, e := r.Get(account.WithIdentity(t.Context(), actor, 1), actor, "rollback")
	if e != nil || state.Granted || state.Revision != 1 {
		t.Fatal(state, e)
	}
}
func TestPlatformAdministratorMongoBootstrapConcurrentAndCorruptMarker(t *testing.T) {
	a, db, s, _ := sessionRevocationFixture(t)
	if e := EnsurePlatformAdministratorSchema(t.Context(), db); e != nil {
		t.Fatal(e)
	}
	_, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"permissions": bson.A{}, "permissionRevision": int64(1)}})
	if e != nil {
		t.Fatal(e)
	}
	adminVerifiedEmail(t, db, s.AuthID)
	r, _ := NewPlatformAdministratorRepository(a, true)
	results := make(chan d.BootstrapResult, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, e := r.Bootstrap(t.Context(), s.AuthID)
			if e != nil {
				t.Error(e)
			}
			results <- out
		}()
	}
	wg.Wait()
	close(results)
	applied := 0
	event := ""
	for result := range results {
		if result.Applied {
			applied++
		}
		if event == "" {
			event = result.EventID
		}
		if event == "" || event != result.EventID {
			t.Fatal(result)
		}
	}
	if applied != 1 {
		t.Fatal(applied)
	}
	// Consumed initialization is independent of current email and membership.
	_, e = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"permissions": bson.A{}}})
	if e != nil {
		t.Fatal(e)
	}
	_, _ = db.Collection(EmailBindingCollection).DeleteMany(t.Context(), bson.M{})
	r.recoveryReady = false
	result, e := r.Bootstrap(t.Context(), s.AuthID)
	if e != nil || result.Applied || result.EventID != event {
		t.Fatal(result, e)
	}
	_, e = db.Collection(AuthenticationRuntimeCollection).UpdateOne(t.Context(), bson.M{"_id": bootstrapMarker}, bson.M{"$unset": bson.M{"bundleVersion": ""}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Bootstrap(t.Context(), s.AuthID); !errors.Is(e, d.ErrUnavailable) {
		t.Fatal(e)
	}
}
func TestPlatformAdministratorMongoUnknownCommit(t *testing.T) {
	_, db, actor := administratorFixture(t)
	a, appName := sessionRevocationFaultRepository(t, db)
	r, _ := NewPlatformAdministratorRepository(a, true)
	adminCandidate(t, db, "unknown")
	admin := db.Client().Database("admin")
	if e := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	})
	ctx, cancel := context.WithTimeout(account.WithIdentity(t.Context(), actor, 1), 150*time.Millisecond)
	defer cancel()
	out, e := r.Manage(ctx, d.Command{ActorAuthID: actor, SubjectAuthID: "unknown", Action: "GRANT", Reason: "test", ExpectedRevision: 1})
	if e == nil || out.AuthID != "" {
		t.Fatal(out, e)
	}
}
