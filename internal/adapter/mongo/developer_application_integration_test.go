package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	d "iwut-auth-center/internal/developer/domain"
	"reflect"
	"sync"
	"testing"
	"time"
)

func developerFixture(t *testing.T) (*DeveloperApplicationRepository, *m.Database, SessionDocument) {
	t.Helper()
	a, db, s, _ := sessionRevocationFixture(t)
	if err := EnsureDeveloperApplicationSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureEmailAccountSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	_, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"developerStatus": nil, "developerRevision": int64(0), "permissions": bson.A{"future.permission"}, "permissionRevision": int64(5), "profile": bson.M{"field": "kept"}, "associationGroupId": "kept"}})
	if err != nil {
		t.Fatal(err)
	}
	bindingID := uuid.NewString()
	if _, err = db.Collection(EmailDirectoryCollection).InsertOne(t.Context(), emailDirectoryDocument{AuthID: s.AuthID, LoginBindingID: bindingID, Revision: 2, LoginRoleRevision: 2, VerifiedCount: 1}); err != nil {
		t.Fatal(err)
	}
	_, err = db.Collection(EmailBindingCollection).InsertOne(t.Context(), emailBindingDocument{BindingID: bindingID, AuthID: s.AuthID, Email: "student@example.test", VerifiedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := NewDeveloperApplicationRepository(a)
	return r, db, s
}
func developerApply(s d.ApplicationState) (d.HandleClaim, error) {
	return developerApplyName("Alice")(s)
}
func developerApplyName(name string) func(d.ApplicationState) (d.HandleClaim, error) {
	return func(s d.ApplicationState) (d.HandleClaim, error) {
		claim, err := s.Apply(true, name)
		if err != nil || !claim {
			return d.HandleClaim{}, err
		}
		handle, _ := d.NormalizeDeveloperHandle(name)
		return d.HandleClaim{DeveloperHandle: handle}, nil
	}
}
func developerRead(s d.ApplicationState) (d.HandleClaim, error) { return d.HandleClaim{}, nil }
func TestDeveloperMongoConcurrentActivationPreservesAccount(t *testing.T) {
	r, db, s := developerFixture(t)
	var before bson.M
	if e := db.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": s.AuthID}).Decode(&before); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan d.ApplicationState, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply)
			if e != nil {
				t.Error(e)
				return
			}
			results <- out
		}()
	}
	wg.Wait()
	close(results)
	var at time.Time
	for out := range results {
		if out.Status != d.DeveloperStatusApproved || out.ActivatedAt == nil {
			t.Fatal(out)
		}
		if at.IsZero() {
			at = *out.ActivatedAt
		}
		if !at.Equal(*out.ActivatedAt) {
			t.Fatal("reset activation time")
		}
	}
	for _, c := range []string{DeveloperActivationCollection, DeveloperApplicationAuditCollection} {
		n, e := db.Collection(c).CountDocuments(t.Context(), bson.M{})
		if e != nil || n != 1 {
			t.Fatal(c, n, e)
		}
	}
	var after bson.M
	if e := db.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": s.AuthID}).Decode(&after); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"authId", "profile", "permissions", "permissionRevision", "associationGroupId"} {
		if !reflect.DeepEqual(before[key], after[key]) {
			t.Fatal("overwritten", key)
		}
	}
	var event bson.M
	if e := db.Collection(DeveloperApplicationAuditCollection).FindOne(t.Context(), bson.M{}).Decode(&event); e != nil {
		t.Fatal(e)
	}
	if event["actorAuthId"] != s.AuthID || event["subjectAuthId"] != s.AuthID || event["emailBindingRevision"] != int64(2) || event["beforeStatus"] != nil || event["afterStatus"] != "APPROVED" || event["email"] != nil {
		t.Fatal(event)
	}
	for _, status := range []string{"PENDING", "REJECTED", "SUSPENDED"} {
		_, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"developerStatus": status, "developerRevision": int64(1)}})
		if e != nil {
			t.Fatal(e)
		}
		_, e = r.Evaluate(t.Context(), s.TokenDigest, developerApply)
		if status == "PENDING" && !errors.Is(e, d.ErrApplicationExists) || status != "PENDING" && !errors.Is(e, d.ErrReapplication) {
			t.Fatal(status, e)
		}
	}
}
func TestDeveloperMongoAuditFailureAndUnknownCommit(t *testing.T) {
	t.Run("audit rollback", func(t *testing.T) {
		r, db, s := developerFixture(t)
		// A database validator fails at the final insert after state and activation writes.
		if e := db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: DeveloperApplicationAuditCollection}, {Key: "validator", Value: bson.M{"neverPresent": bson.M{"$exists": true}}}}).Err(); e != nil {
			t.Fatal(e)
		}
		if out, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply); !errors.Is(e, d.ErrApplicationUnavailable) || out.AuthID != "" {
			t.Fatal(out, e)
		}
		state, e := r.Evaluate(t.Context(), s.TokenDigest, developerRead)
		if e != nil || state.Status != "" || state.ActivatedAt != nil {
			t.Fatal(state, e)
		}
		n, e := db.Collection(DeveloperActivationCollection).CountDocuments(t.Context(), bson.M{})
		if e != nil || n != 0 {
			t.Fatal(n, e)
		}
	})
	t.Run("unknown commit", func(t *testing.T) {
		_, db, s := developerFixture(t)
		a, appName := sessionRevocationFaultRepository(t, db)
		r, _ := NewDeveloperApplicationRepository(a)
		admin := db.Client().Database("admin")
		if e := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); e != nil {
			t.Fatal(e)
		}
		off := func() {
			_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
		}
		t.Cleanup(off)
		ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
		defer cancel()
		if out, e := r.Evaluate(ctx, s.TokenDigest, developerApply); !errors.Is(e, d.ErrApplicationUnavailable) || out.AuthID != "" {
			t.Fatal(out, e)
		}
		off()
		out, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply)
		if e != nil || out.Status != d.DeveloperStatusApproved {
			t.Fatal(out, e)
		}
		n, e := db.Collection(DeveloperApplicationAuditCollection).CountDocuments(t.Context(), bson.M{})
		if e != nil || n != 1 {
			t.Fatal(n, e)
		}
	})
}
func TestDeveloperMongoHistoricalAndCorruptState(t *testing.T) {
	for _, tc := range []struct {
		name, collection string
		set              bson.M
		want             error
	}{
		{"missing email", EmailBindingCollection, bson.M{"revision": int64(0), "email": nil}, d.ErrApplicationUnavailable},
		{"unverified", EmailBindingCollection, bson.M{"verifiedAt": nil}, d.ErrApplicationUnavailable},
		{"wrong revision type", EmailDirectoryCollection, bson.M{"revision": int32(1)}, d.ErrApplicationUnavailable},
		{"unknown status", PrincipalCollection, bson.M{"developerStatus": "UNKNOWN"}, d.ErrApplicationUnavailable},
		{"status missing type", PrincipalCollection, bson.M{"developerStatus": 12}, d.ErrApplicationUnavailable},
		{"disabled", PrincipalCollection, bson.M{"accountStatus": "DISABLED"}, d.ErrApplicationSession},
		{"system", PrincipalCollection, bson.M{"principalType": "SYSTEM"}, d.ErrApplicationSession},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, db, s := developerFixture(t)
			if _, e := db.Collection(tc.collection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": tc.set}); e != nil {
				t.Fatal(e)
			}
			if _, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply); !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
		})
	}
	t.Run("historical", func(t *testing.T) {
		r, db, s := developerFixture(t)
		for _, status := range []string{"APPROVED", "PENDING", "REJECTED", "SUSPENDED"} {
			if _, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"developerStatus": status, "developerRevision": int64(1)}}); e != nil {
				t.Fatal(e)
			}
			out, e := r.Evaluate(t.Context(), s.TokenDigest, developerRead)
			if e != nil || string(out.Status) != status || out.ActivatedAt != nil {
				t.Fatal(out, e)
			}
		}
		n, e := db.Collection(DeveloperActivationCollection).CountDocuments(t.Context(), bson.M{})
		if e != nil || n != 0 {
			t.Fatal(n, e)
		}
	})
	t.Run("malformed directory has no login fallback", func(t *testing.T) {
		r, db, s := developerFixture(t)
		if _, e := db.Collection(EmailBindingCollection).ReplaceOne(t.Context(), bson.M{"authId": s.AuthID}, bindingDocument{AuthID: s.AuthID, Revision: 0, PendingID: "proposal"}); e != nil {
			t.Fatal(e)
		}
		if _, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply); !errors.Is(e, d.ErrApplicationUnavailable) {
			t.Fatal(e)
		}
	})
	t.Run("orphan activation", func(t *testing.T) {
		r, db, s := developerFixture(t)
		if _, e := db.Collection(DeveloperActivationCollection).InsertOne(t.Context(), bson.M{"authId": s.AuthID, "activatedAt": time.Now(), "emailBindingRevision": int64(1), "eventId": "event"}); e != nil {
			t.Fatal(e)
		}
		if _, e := r.Evaluate(t.Context(), s.TokenDigest, developerRead); !errors.Is(e, d.ErrApplicationUnavailable) {
			t.Fatal(e)
		}
	})
}

func TestDeveloperMongoUsesSharedSessionAndEmailFence(t *testing.T) {
	for _, mode := range []string{"revoke", "replace email"} {
		t.Run(mode, func(t *testing.T) {
			r, db, s := developerFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			result := make(chan error, 1)
			var once sync.Once
			go func() {
				_, e := r.Evaluate(t.Context(), s.TokenDigest, func(state d.ApplicationState) (d.HandleClaim, error) {
					once.Do(func() { close(entered); <-release })
					return developerApply(state)
				})
				result <- e
			}()
			<-entered
			mutation := make(chan error, 1)
			go func() {
				if mode == "revoke" {
					mutation <- r.authentication.RevokeCurrentSession(t.Context(), s.TokenDigest, time.Now())
					return
				}
				mutation <- r.authentication.WithAuthTransaction(t.Context(), func(tx context.Context) error {
					_, e := db.Collection(EmailBindingCollection).UpdateOne(tx, bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"email": "changed@example.test", "verifiedAt": time.Now()}})
					if e != nil {
						return e
					}
					_, e = db.Collection(EmailDirectoryCollection).UpdateOne(tx, bson.M{"authId": s.AuthID}, bson.M{"$inc": bson.M{"revision": int64(1), "loginRoleRevision": int64(1)}})
					return e
				})
			}()
			select {
			case e := <-mutation:
				t.Fatal("mutation crossed confirmation fence", e)
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			if e := <-result; e != nil {
				t.Fatal(e)
			}
			if e := <-mutation; e != nil {
				t.Fatal(e)
			}
			var activation bson.M
			if e := db.Collection(DeveloperActivationCollection).FindOne(t.Context(), bson.M{"authId": s.AuthID}).Decode(&activation); e != nil {
				t.Fatal(e)
			}
			if activation["emailBindingRevision"] != int64(2) {
				t.Fatal(activation)
			}
			if mode == "revoke" {
				if _, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply); !errors.Is(e, d.ErrApplicationSession) {
					t.Fatal("revoked session passed", e)
				}
			} else {
				out, e := r.Evaluate(t.Context(), s.TokenDigest, developerRead)
				if e != nil || out.EmailRevision != 3 || out.ActivatedAt == nil {
					t.Fatal(out, e)
				}
			}
			var session SessionDocument
			if e := db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": s.SessionID}).Decode(&session); e != nil {
				t.Fatal(e)
			}
			if !session.ExpiresAt.Equal(s.ExpiresAt) || session.LastUsedAt.Before(s.LastUsedAt) {
				t.Fatal("session lifetime or usage changed incorrectly")
			}
		})
	}
	t.Run("email replacement committed first", func(t *testing.T) {
		r, db, s := developerFixture(t)
		if e := r.authentication.WithAuthTransaction(t.Context(), func(tx context.Context) error {
			_, e := db.Collection(EmailBindingCollection).UpdateOne(tx, bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"email": "new@example.test", "revision": int64(3), "verifiedAt": time.Now()}})
			if e != nil {
				return e
			}
			_, e = db.Collection(EmailDirectoryCollection).UpdateOne(tx, bson.M{"authId": s.AuthID}, bson.M{"$inc": bson.M{"revision": int64(1), "loginRoleRevision": int64(1)}})
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if _, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply); e != nil {
			t.Fatal(e)
		}
		var activation bson.M
		if e := db.Collection(DeveloperActivationCollection).FindOne(t.Context(), bson.M{"authId": s.AuthID}).Decode(&activation); e != nil {
			t.Fatal(e)
		}
		if activation["emailBindingRevision"] != int64(3) {
			t.Fatal(activation)
		}
	})
}
