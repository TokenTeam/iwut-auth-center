package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	account "iwut-auth-center/internal/account/domain"
	identitydomain "iwut-auth-center/internal/identity/domain"
	"iwut-auth-center/internal/reviewer/domain"
	"math"
	"sync"
	"testing"
	"time"
)

func reviewerFixture(t *testing.T, skipBootstrap ...bool) (*ReviewerRepository, *drivermongo.Database, string) {
	t.Helper()
	a, db, s, _ := sessionRevocationFixture(t)
	if err := EnsureReviewerSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	_, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"permissions": bson.A{}, "permissionRevision": int64(1), "developerStatus": nil}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Collection(PrincipalCollection).InsertOne(t.Context(), bson.M{"authId": "admin", "principalType": "USER", "accountStatus": "ACTIVE", "accountRevision": int64(1), "permissions": bson.A{}, "permissionRevision": int64(1), "developerStatus": nil})
	if err != nil {
		t.Fatal(err)
	}
	if len(skipBootstrap) == 0 {
		seedAdministrator(t, a, "admin")
	} else {
		if e := EnsurePlatformAdministratorSchema(t.Context(), db); e != nil {
			t.Fatal(e)
		}
		adminVerifiedEmail(t, db, s.AuthID)
	}
	r, _ := NewReviewerRepository(a, true)
	return r, db, s.AuthID
}
func TestReviewerMongoAtomicAuditConcurrencyAndSubjectRules(t *testing.T) {
	r, db, id := reviewerFixture(t)
	c := domain.Command{Permission: domain.Reviewer, ActorAuthID: "admin", SubjectAuthID: id, Action: "GRANT", Reason: "review onboarding", ExpectedRevision: 1}
	var wg sync.WaitGroup
	results := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Manage(account.WithIdentity(t.Context(), "admin", 1), c)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, domain.ErrConflict) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	state, err := r.Get(account.WithIdentity(t.Context(), "admin", 1), "admin", id)
	if err != nil || state.Revision != 2 || !state.Has(domain.Reviewer) {
		t.Fatal(state, err)
	}
	count, _ := db.Collection(PermissionAuditCollection).CountDocuments(t.Context(), bson.M{})
	if count != 1 {
		t.Fatal(count)
	}
	for _, subject := range []string{"missing", "system", "disabled"} {
		if subject != "missing" {
			kind, status := "USER", "DISABLED"
			if subject == "system" {
				kind, status = "SYSTEM", "ACTIVE"
			}
			_, err = db.Collection(PrincipalCollection).InsertOne(t.Context(), bson.M{"authId": subject, "principalType": kind, "accountStatus": status, "permissions": bson.A{}, "permissionRevision": int64(1)})
			if err != nil {
				t.Fatal(err)
			}
		}
		bad := c
		bad.SubjectAuthID = subject
		if _, err = r.Manage(account.WithIdentity(t.Context(), "admin", 1), bad); !errors.Is(err, domain.ErrSubject) {
			t.Fatal(subject, err)
		}
	}
	_, err = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": "admin"}, bson.M{"$set": bson.M{"permissions": bson.A{}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Get(account.WithIdentity(t.Context(), "admin", 1), "admin", id); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal(err)
	}
	if _, err = r.Manage(account.WithIdentity(t.Context(), "admin", 1), c); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal(err)
	}
}
func TestReviewerMongoBootstrapDurableNoResurrection(t *testing.T) {
	r, db, id := reviewerFixture(t, true)
	applied, err := r.Bootstrap(t.Context(), id)
	if err != nil || !applied {
		t.Fatal(applied, err)
	}
	applied, err = r.Bootstrap(t.Context(), id)
	if err != nil || applied {
		t.Fatal(applied, err)
	}
	var audit bson.M
	if err = db.Collection(PlatformAdminAuditCollection).FindOne(t.Context(), bson.M{"subjectAuthId": id}).Decode(&audit); err != nil {
		t.Fatal(err)
	}
	if audit["actorType"] != "BOOTSTRAP_COMMAND" || audit["actorAuthId"] != nil {
		t.Fatal(audit)
	}
	state, err := r.Get(account.WithIdentity(t.Context(), id, 1), id, id)
	if err != nil || state.Has(domain.Reviewer) || !state.Has(domain.Manager) || state.Revision != 2 {
		t.Fatal(state, err)
	}
	_, err = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": id}, bson.M{"$set": bson.M{"permissions": bson.A{}}, "$inc": bson.M{"permissionRevision": int64(1)}})
	if err != nil {
		t.Fatal(err)
	}
	applied, err = r.Bootstrap(t.Context(), id)
	if err != nil || applied {
		t.Fatal(applied, err)
	}
	state, err = r.read(t.Context(), id)
	if err != nil || state.Has(domain.Manager) || state.Revision != 3 {
		t.Fatal(state, err)
	}
	if _, err = r.Bootstrap(t.Context(), "admin"); !errors.Is(err, domain.ErrBootstrapConsumed) {
		t.Fatal(err)
	}
	count, _ := db.Collection(PlatformAdminAuditCollection).CountDocuments(t.Context(), bson.M{})
	if count != 1 {
		t.Fatal(count)
	}
}
func TestReviewerMongoAuditFailureRollsBackAndRevisionExhaustion(t *testing.T) {
	r, db, id := reviewerFixture(t)
	// Occupy the next audit revision: insertion fails after the permission update.
	_, err := db.Collection(PermissionAuditCollection).InsertOne(t.Context(), bson.M{"eventId": "existing", "subjectAuthId": id, "afterRevision": int64(2)})
	if err != nil {
		t.Fatal(err)
	}
	c := domain.Command{Permission: domain.Reviewer, ActorAuthID: "admin", SubjectAuthID: id, Action: "GRANT", Reason: "test", ExpectedRevision: 1}
	if result, err := r.Manage(account.WithIdentity(t.Context(), "admin", 1), c); !errors.Is(err, domain.ErrUnavailable) || result.AuthID != "" {
		t.Fatal(result, err)
	}
	s, err := r.Get(account.WithIdentity(t.Context(), "admin", 1), "admin", id)
	if err != nil || s.Revision != 1 || s.Has(domain.Reviewer) {
		t.Fatal(s, err)
	}
	_, err = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": id}, bson.M{"$set": bson.M{"permissionRevision": int64(math.MaxInt64)}})
	if err != nil {
		t.Fatal(err)
	}
	c.ExpectedRevision = math.MaxInt64
	if _, err = r.Manage(account.WithIdentity(t.Context(), "admin", 1), c); !errors.Is(err, domain.ErrExhausted) {
		t.Fatal(err)
	}
}
func TestReviewerMongoRevokeSynchronizesIdentityIssuance(t *testing.T) {
	for _, permission := range []string{domain.ProfileReviewer, domain.Reviewer} {
		t.Run(permission, func(t *testing.T) {
			issuer, db, session, _, _, _ := identityFixture(t)
			if err := EnsureReviewerSchema(t.Context(), db); err != nil {
				t.Fatal(err)
			}
			_, err := db.Collection(PrincipalCollection).InsertOne(t.Context(), bson.M{"authId": "admin", "principalType": "USER", "accountStatus": "ACTIVE", "accountRevision": int64(1), "permissions": bson.A{}, "permissionRevision": int64(1)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": session.AuthID}, bson.M{"$set": bson.M{"permissions": bson.A{domain.ProfileReviewer, domain.Reviewer}}})
			if err != nil {
				t.Fatal(err)
			}
			seedAdministrator(t, issuer.authentication, "admin")
			repo, _ := NewReviewerRepository(issuer.authentication)
			entered, release := make(chan struct{}), make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- issuer.WithSession(t.Context(), session.TokenDigest, func(s identitydomain.Snapshot, _ time.Time) error { close(entered); <-release; return nil })
			}()
			<-entered
			revoked := make(chan error, 1)
			go func() {
				_, err := repo.Manage(account.WithIdentity(t.Context(), "admin", 1), domain.Command{Permission: permission, ActorAuthID: "admin", SubjectAuthID: session.AuthID, Action: "REVOKE", Reason: "access ended", ExpectedRevision: 1})
				revoked <- err
			}()
			select {
			case err := <-revoked:
				t.Fatal("revoke passed uncommitted signing boundary", err)
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if err = <-revoked; err != nil {
				t.Fatal(err)
			}
			if err = issuer.WithSession(t.Context(), session.TokenDigest, func(s identitydomain.Snapshot, _ time.Time) error {
				if len(s.Permissions) != 1 || s.Permissions[0] == permission || s.PermissionRevision != 2 {
					t.Fatal(s)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReviewerMongoUnknownCommitReturnsNoSuccess(t *testing.T) {
	_, db, id := reviewerFixture(t)
	authentication, appName := sessionRevocationFaultRepository(t, db)
	r, _ := NewReviewerRepository(authentication)
	admin := db.Client().Database("admin")
	if err := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	})
	ctx, cancel := context.WithTimeout(account.WithIdentity(t.Context(), "admin", 1), 150*time.Millisecond)
	defer cancel()
	result, err := r.Manage(ctx, domain.Command{Permission: domain.Reviewer, ActorAuthID: "admin", SubjectAuthID: id, Action: "GRANT", Reason: "test", ExpectedRevision: 1})
	if err == nil || result.AuthID != "" {
		t.Fatal(result, err)
	}
}

func TestReviewPermissionsMongoSharedRevisionAndAudit(t *testing.T) {
	r, db, id := reviewerFixture(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, permission := range []string{domain.ProfileReviewer, domain.Reviewer} {
		go func() {
			<-start
			_, err := r.Manage(account.WithIdentity(t.Context(), "admin", 1), domain.Command{ActorAuthID: "admin", SubjectAuthID: id, Permission: permission, Action: "GRANT", Reason: "onboarding", ExpectedRevision: 1})
			results <- err
		}()
	}
	close(start)
	success := 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if !errors.Is(err, domain.ErrConflict) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	s, err := r.Get(account.WithIdentity(t.Context(), "admin", 1), "admin", id)
	if err != nil || s.Revision != 2 || len(s.Permissions) != 1 {
		t.Fatal(s, err)
	}
	remaining := domain.ProfileReviewer
	if s.Has(remaining) {
		remaining = domain.Reviewer
	}
	s, err = r.Manage(account.WithIdentity(t.Context(), "admin", 1), domain.Command{ActorAuthID: "admin", SubjectAuthID: id, Permission: remaining, Action: "GRANT", Reason: "retry", ExpectedRevision: s.Revision})
	if err != nil || s.Revision != 3 || !s.Has(domain.ProfileReviewer) || !s.Has(domain.Reviewer) {
		t.Fatal(s, err)
	}
	s, err = r.Manage(account.WithIdentity(t.Context(), "admin", 1), domain.Command{ActorAuthID: "admin", SubjectAuthID: id, Permission: domain.Reviewer, Action: "REVOKE", Reason: "version only", ExpectedRevision: s.Revision})
	if err != nil || s.Revision != 4 || !s.Has(domain.ProfileReviewer) || s.Has(domain.Reviewer) {
		t.Fatal(s, err)
	}
	for _, permission := range []string{domain.ProfileReviewer, domain.Reviewer} {
		var audit bson.M
		err := db.Collection(PermissionAuditCollection).FindOne(t.Context(), bson.M{"subjectAuthId": id, "permission": permission, "action": "GRANT"}).Decode(&audit)
		if err != nil || audit["actorAuthId"] != "admin" {
			t.Fatal(audit, err)
		}
	}
	count, err := db.Collection(PermissionAuditCollection).CountDocuments(t.Context(), bson.M{"subjectAuthId": id})
	if err != nil || count != 3 {
		t.Fatal(count, err)
	}
}
