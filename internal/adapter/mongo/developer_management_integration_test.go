package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	account "iwut-auth-center/internal/account/domain"
	d "iwut-auth-center/internal/developer/domain"
	od "iwut-auth-center/internal/oauth/domain"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"
)

func developerManagementFixture(t *testing.T) (*DeveloperManagementRepository, *m.Database, string) {
	t.Helper()
	admin, db, actor := administratorFixture(t)
	if e := EnsureDeveloperManagementSchema(t.Context(), db); e != nil {
		t.Fatal(e)
	}
	adminCandidate(t, db, "developer")
	_, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": "developer"}, bson.M{"$set": bson.M{"accountRevision": int64(1), "developerRevision": int64(1), "developerStatus": "APPROVED", "profile": bson.M{"kept": true}}})
	if e != nil {
		t.Fatal(e)
	}
	r, _ := NewDeveloperManagementRepository(admin.authentication, true)
	return r, db, actor
}
func TestDeveloperManagementMongoAtomicCancellationAndPreservation(t *testing.T) {
	r, db, actor := developerManagementFixture(t)
	ctx := account.WithIdentity(t.Context(), actor, 1)
	var before bson.M
	if e := db.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": "developer"}).Decode(&before); e != nil {
		t.Fatal(e)
	}
	op := uuid.NewString()
	if _, e := db.Collection("auth_account_owner_exit_operations").InsertOne(ctx, bson.M{"authId": "developer", "operationId": op, "purpose": "DEVELOPER_WITHDRAWAL", "decision": "PENDING", "expiresAt": time.Now().Add(time.Minute), "attempts": int64(3), "notificationPending": false}); e != nil {
		t.Fatal(e)
	}
	out, e := r.ManageDeveloperStatus(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: "developer", Action: "SUSPEND", Reason: "governance", ExpectedRevision: 1})
	if e != nil || out.Status != "SUSPENDED" || out.Revision != 2 || out.StatusChangedAt == nil {
		t.Fatal(out, e)
	}
	var after, cancelled bson.M
	_ = db.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": "developer"}).Decode(&after)
	_ = db.Collection("auth_account_owner_exit_operations").FindOne(ctx, bson.M{"operationId": op}).Decode(&cancelled)
	for _, field := range []string{"accountRevision", "accountStatus", "permissions", "permissionRevision", "profile"} {
		if !reflect.DeepEqual(before[field], after[field]) {
			t.Fatal(field, before[field], after[field])
		}
	}
	if cancelled["decision"] != "CANCELLED" || cancelled["notificationPending"] != true || cancelled["attempts"] != int64(3) || cancelled["nextAttemptAt"] == nil {
		t.Fatal(cancelled)
	}
	if _, e = r.ManageDeveloperStatus(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: "developer", Action: "SUSPEND", Reason: "retry", ExpectedRevision: 1}); !errors.Is(e, d.ErrManagementConflict) {
		t.Fatal(e)
	}
	count, _ := db.Collection(DeveloperLifecycleAuditCollection).CountDocuments(ctx, bson.M{})
	if count != 1 {
		t.Fatal(count)
	}
	r.recoveryReady = false
	if _, e = r.ManageDeveloperStatus(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: "developer", Action: "RESTORE", Reason: "done", ExpectedRevision: 2}); !errors.Is(e, d.ErrRestoreBlocked) {
		t.Fatal(e)
	}
	r.recoveryReady = true
	_, _ = db.Collection(EmailBindingCollection).DeleteOne(ctx, bson.M{"authId": "developer"})
	if _, e = r.ManageDeveloperStatus(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: "developer", Action: "RESTORE", Reason: "done", ExpectedRevision: 2}); !errors.Is(e, d.ErrManagementUnavailable) {
		t.Fatal(e)
	}
	adminVerifiedEmail(t, db, "developer")
	_, _ = db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": "developer"}, bson.M{"$set": bson.M{"accountStatus": "DISABLED"}})
	out, e = r.ManageDeveloperStatus(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: "developer", Action: "RESTORE", Reason: "done", ExpectedRevision: 2})
	if e != nil || out.AccountStatus != "DISABLED" || out.Status != "APPROVED" {
		t.Fatal(out, e)
	}
}
func TestDeveloperManagementMongoCASCorruptionAndAuditRollback(t *testing.T) {
	r, db, actor := developerManagementFixture(t)
	ctx := account.WithIdentity(t.Context(), actor, 1)
	c := d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: "developer", Action: "SUSPEND", Reason: "test", ExpectedRevision: 1}
	var wg sync.WaitGroup
	ch := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := r.ManageDeveloperStatus(ctx, c); ch <- e }()
	}
	wg.Wait()
	close(ch)
	success := 0
	for e := range ch {
		if e == nil {
			success++
		} else if !errors.Is(e, d.ErrManagementConflict) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	if e := db.RunCommand(ctx, bson.D{{Key: "collMod", Value: DeveloperLifecycleAuditCollection}, {Key: "validator", Value: bson.M{"action": bson.M{"$ne": "RESTORE"}}}}).Err(); e != nil {
		t.Fatal(e)
	}
	if _, e := r.ManageDeveloperStatus(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: "developer", Action: "RESTORE", Reason: "test", ExpectedRevision: 2}); !errors.Is(e, d.ErrManagementUnavailable) {
		t.Fatal(e)
	}
	state, e := r.GetManagedDeveloperStatus(ctx, actor, "developer")
	if e != nil || state.Status != "SUSPENDED" || state.Revision != 2 {
		t.Fatal(state, e)
	}
	for _, status := range []string{"PENDING", "REJECTED", "WITHDRAWN"} {
		_, _ = db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": "developer"}, bson.M{"$set": bson.M{"developerStatus": status}})
		if _, e := r.ManageDeveloperStatus(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: "developer", Action: "RESTORE", Reason: "test", ExpectedRevision: 2}); !errors.Is(e, d.ErrManagementConflict) {
			t.Fatal(status, e)
		}
	}
	_, _ = db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": "developer"}, bson.M{"$set": bson.M{"developerRevision": int64(math.MaxInt64), "developerStatus": "APPROVED"}})
	c.ExpectedRevision = math.MaxInt64
	if _, e := r.ManageDeveloperStatus(ctx, c); !errors.Is(e, d.ErrDeveloperRevisionExhausted) {
		t.Fatal(e)
	}
	_, _ = db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": "developer"}, bson.M{"$set": bson.M{"developerRevision": int32(1)}})
	if _, e := r.GetManagedDeveloperStatus(ctx, actor, "developer"); !errors.Is(e, d.ErrManagementUnavailable) {
		t.Fatal(e)
	}
}
func TestDeveloperManagementMongoOAuthTemporaryOwnerRestriction(t *testing.T) {
	f := newOAuthFixture(t)
	db := f.auth.r.database
	actor := f.auth.c.AuthID
	_, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": actor}, bson.M{"$set": bson.M{"permissions": bson.A{}, "permissionRevision": int64(1), "developerRevision": int64(1)}})
	if e != nil {
		t.Fatal(e)
	}
	seedAdministrator(t, f.auth.r, actor)
	if e = EnsureDeveloperManagementSchema(t.Context(), db); e != nil {
		t.Fatal(e)
	}
	r, _ := NewDeveloperManagementRepository(f.auth.r, true)
	ctx := account.WithIdentity(t.Context(), actor, 1)
	token := f.tokens(t, "openid", "offline_access")
	revoked := f.tokens(t, "openid")
	if e = f.service.RevokeToken(t.Context(), od.ClientProof{ClientID: "public-client"}, revoked.AccessToken, ""); e != nil {
		t.Fatal(e)
	}
	grants, e := f.service.ListGrants(t.Context(), f.session, "", 50)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.ManageDeveloperStatus(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: actor, Action: "SUSPEND", Reason: "owner suspended", ExpectedRevision: 1}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.UserInfo(t.Context(), token.AccessToken); e == nil {
		t.Fatal("suspended owner accepted")
	}
	if _, e = f.service.Refresh(t.Context(), od.ClientProof{ClientID: "public-client"}, token.RefreshToken, nil); e == nil {
		t.Fatal("suspended refresh accepted")
	}
	after, e := f.service.ListGrants(t.Context(), f.session, "", 50)
	if e != nil || !reflect.DeepEqual(grants, after) {
		t.Fatal("ordinary grants or session changed", after, e)
	}
	if _, e = r.ManageDeveloperStatus(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: actor, Action: "RESTORE", Reason: "recovered", ExpectedRevision: 2}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.UserInfo(t.Context(), token.AccessToken); e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.Refresh(t.Context(), od.ClientProof{ClientID: "public-client"}, token.RefreshToken, nil); e != nil {
		t.Fatal("temporary pause consumed refresh", e)
	}
	if _, e = f.service.UserInfo(t.Context(), revoked.AccessToken); e == nil {
		t.Fatal("revoked token resurrected")
	}
}
func TestDeveloperManagementMongoUnknownCommit(t *testing.T) {
	_, db, actor := developerManagementFixture(t)
	a, appName := sessionRevocationFaultRepository(t, db)
	r, _ := NewDeveloperManagementRepository(a, true)
	admin := db.Client().Database("admin")
	if e := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	})
	ctx, cancel := context.WithTimeout(account.WithIdentity(t.Context(), actor, 1), 150*time.Millisecond)
	defer cancel()
	out, e := r.ManageDeveloperStatus(ctx, d.ManageDeveloperCommand{ActorAuthID: actor, SubjectAuthID: "developer", Action: "SUSPEND", Reason: "test", ExpectedRevision: 1})
	if e == nil || out.AuthID != "" {
		t.Fatal(out, e)
	}
}
