package mongo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	d "iwut-auth-center/internal/developer/domain"
)

func developerAdditionalUser(t *testing.T, db *m.Database) SessionDocument {
	t.Helper()
	p, _ := deviceprotocol.New("test")
	authID := uuid.NewString()
	credentialID, _ := p.NewID()
	sessionID, _ := p.NewID()
	_, digest, _ := p.NewSessionToken()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	public := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	fingerprint, _ := p.Fingerprint(public)
	now := time.Now().UTC().Truncate(time.Millisecond)
	session := SessionDocument{SessionID: sessionID, AuthID: authID, AuthenticationMethod: "DEVICE_CREDENTIAL", CredentialID: credentialID, TokenDigest: digest, CreatedAt: now, AuthenticatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}
	for collection, doc := range map[string]any{
		PrincipalCollection:    bson.M{"authId": authID, "principalType": "USER", "accountStatus": "ACTIVE", "developerStatus": nil, "permissions": bson.A{}, "permissionRevision": int64(1)},
		CredentialCollection:   CredentialDocument{AuthID: authID, CredentialID: credentialID, ProtocolVersion: "iwut-device-v1", PublicKey: public, Fingerprint: fingerprint, CreatedAt: now},
		SessionCollection:      session,
		EmailBindingCollection: bindingDocument{AuthID: authID, Email: authID + "@example.test", Revision: 1, VerifiedAt: now},
	} {
		if _, e := db.Collection(collection).InsertOne(t.Context(), doc); e != nil {
			t.Fatal(e)
		}
	}
	return session
}
func TestDeveloperHandleMongoConcurrentNamesAndRetention(t *testing.T) {
	t.Run("two accounts equivalent names", func(t *testing.T) {
		r, db, first := developerFixture(t)
		second := developerAdditionalUser(t, db)
		type result struct {
			s     SessionDocument
			state d.ApplicationState
			err   error
		}
		results := make(chan result, 2)
		start := make(chan struct{})
		for i, s := range []SessionDocument{first, second} {
			go func() {
				<-start
				name := []string{"Alice", "ALICE"}[i]
				state, e := r.Evaluate(t.Context(), s.TokenDigest, developerApplyName(name))
				results <- result{s, state, e}
			}()
		}
		close(start)
		a, b := <-results, <-results
		if a.err != nil {
			a, b = b, a
		}
		if a.err != nil || !errors.Is(b.err, d.ErrHandleTaken) {
			t.Fatal(a.err, b.err)
		}
		if a.state.DeveloperHandle != "alice" {
			t.Fatal(a.state)
		}
		loser, e := r.Evaluate(t.Context(), b.s.TokenDigest, developerRead)
		if e != nil || loser.Status != "" || loser.DeveloperHandle != "" || loser.ActivatedAt != nil {
			t.Fatal(loser, e)
		}
		for _, collection := range []string{DeveloperHandleCollection, DeveloperActivationCollection, DeveloperApplicationAuditCollection} {
			n, e := db.Collection(collection).CountDocuments(t.Context(), bson.M{})
			if e != nil || n != 1 {
				t.Fatal(collection, n, e)
			}
		}
		if _, e = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": a.s.AuthID}, bson.M{"$set": bson.M{"developerStatus": "SUSPENDED"}}); e != nil {
			t.Fatal(e)
		}
		if _, e = r.Evaluate(t.Context(), a.s.TokenDigest, developerApplyName("alice")); !errors.Is(e, d.ErrReapplication) {
			t.Fatal(e)
		}
		if _, e = r.Evaluate(t.Context(), b.s.TokenDigest, developerApplyName("Alice")); !errors.Is(e, d.ErrHandleTaken) {
			t.Fatal("suspension released name", e)
		}
		suspended, e := r.Evaluate(t.Context(), a.s.TokenDigest, developerRead)
		if e != nil || suspended.DeveloperHandle != "alice" {
			t.Fatal(suspended, e)
		}
	})
	t.Run("one account different names", func(t *testing.T) {
		r, db, s := developerFixture(t)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		start := make(chan struct{})
		for _, name := range []string{"Alice", "Bob"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, e := r.Evaluate(t.Context(), s.TokenDigest, developerApplyName(name))
				errs <- e
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		success, conflict := 0, 0
		for e := range errs {
			if e == nil {
				success++
			} else if errors.Is(e, d.ErrHandleChange) {
				conflict++
			} else {
				t.Fatal(e)
			}
		}
		if success != 1 || conflict != 1 {
			t.Fatal(success, conflict)
		}
		for _, collection := range []string{DeveloperHandleCollection, DeveloperActivationCollection, DeveloperApplicationAuditCollection} {
			n, e := db.Collection(collection).CountDocuments(t.Context(), bson.M{})
			if e != nil || n != 1 {
				t.Fatal(collection, n, e)
			}
		}
	})
}
func TestDeveloperHandleMongoLegacyClaimAndIndexUpgrade(t *testing.T) {
	r, db, s := developerFixture(t)
	audit := db.Collection(DeveloperApplicationAuditCollection)
	if e := audit.Indexes().DropOne(t.Context(), "developer_subject_action_unique"); e != nil {
		t.Fatal(e)
	}
	if _, e := audit.Indexes().CreateOne(t.Context(), m.IndexModel{Keys: bson.D{{Key: "subjectAuthId", Value: 1}}, Options: options.Index().SetUnique(true)}); e != nil {
		t.Fatal(e)
	}
	then := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	if _, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"developerStatus": "APPROVED"}}); e != nil {
		t.Fatal(e)
	}
	legacyEvent := bson.M{"eventId": "legacy", "actorAuthId": s.AuthID, "subjectAuthId": s.AuthID, "action": developerApplyAction, "beforeStatus": nil, "afterStatus": "APPROVED", "emailBindingRevision": int64(1), "occurredAt": then, "result": "APPROVED"}
	if _, e := audit.InsertOne(t.Context(), legacyEvent); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Collection(DeveloperActivationCollection).InsertOne(t.Context(), bson.M{"authId": s.AuthID, "activatedAt": then, "eventId": "legacy", "emailBindingRevision": int64(1)}); e != nil {
		t.Fatal(e)
	}
	var oldEvent, oldActivation bson.Raw
	if e := audit.FindOne(t.Context(), bson.M{"eventId": "legacy"}).Decode(&oldEvent); e != nil {
		t.Fatal(e)
	}
	if e := db.Collection(DeveloperActivationCollection).FindOne(t.Context(), bson.M{"authId": s.AuthID}).Decode(&oldActivation); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if e := EnsureDeveloperApplicationSchema(t.Context(), db); e != nil {
			t.Fatal(e)
		}
	}
	cursor, e := audit.Indexes().List(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer cursor.Close(t.Context())
	compound := false
	for cursor.Next(t.Context()) {
		var index bson.M
		if e = cursor.Decode(&index); e != nil {
			t.Fatal(e)
		}
		if index["name"] == "subjectAuthId_1" {
			t.Fatal("old unique index retained")
		}
		if index["name"] == "developer_subject_action_unique" {
			compound = index["unique"] == true
		}
	}
	if e = cursor.Err(); e != nil || !compound {
		t.Fatal(e, compound)
	}
	state, e := r.Evaluate(t.Context(), s.TokenDigest, developerRead)
	if e != nil || state.DeveloperHandle != "" || len(state.Blockers(true)) != 0 {
		t.Fatal(state, e)
	}
	claimed, e := r.Evaluate(t.Context(), s.TokenDigest, developerApplyName("ALIce"))
	if e != nil || claimed.DeveloperHandle != "alice" || claimed.ActivatedAt == nil || !claimed.ActivatedAt.Equal(then) {
		t.Fatal(claimed, e)
	}
	repeated, e := r.Evaluate(t.Context(), s.TokenDigest, developerApplyName("Alice"))
	if e != nil || !repeated.ActivatedAt.Equal(then) {
		t.Fatal(repeated, e)
	}
	var after bson.Raw
	if e = audit.FindOne(t.Context(), bson.M{"eventId": "legacy"}).Decode(&after); e != nil || !bytes.Equal(after, oldEvent) {
		t.Fatal("old audit changed", e)
	}
	if e = db.Collection(DeveloperActivationCollection).FindOne(t.Context(), bson.M{"authId": s.AuthID}).Decode(&after); e != nil || !bytes.Equal(after, oldActivation) {
		t.Fatal("activation changed", e)
	}
	count, e := audit.CountDocuments(t.Context(), bson.M{})
	if e != nil || count != 2 {
		t.Fatal(count, e)
	}
	count, e = audit.CountDocuments(t.Context(), bson.M{"action": developerClaimAction, "developerHandle": "alice", "emailBindingRevision": int64(2)})
	if e != nil || count != 1 {
		t.Fatal(count, e)
	}
	if _, e = r.Evaluate(t.Context(), s.TokenDigest, developerApplyName("Bob")); !errors.Is(e, d.ErrHandleChange) {
		t.Fatal(e)
	}
}
func TestDeveloperHandleMongoHistoricalWithoutActivationAndGates(t *testing.T) {
	r, db, s := developerFixture(t)
	if _, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"developerStatus": "APPROVED"}}); e != nil {
		t.Fatal(e)
	}
	closed := func(s d.ApplicationState) (d.HandleClaim, error) {
		_, e := s.Apply(false, "Alice")
		return d.HandleClaim{}, e
	}
	if _, e := r.Evaluate(t.Context(), s.TokenDigest, closed); !errors.Is(e, d.ErrEmailLoginUnavailable) {
		t.Fatal(e)
	}
	state, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply)
	if e != nil || state.DeveloperHandle != "alice" || state.ActivatedAt != nil {
		t.Fatal(state, e)
	}
	for collection, want := range map[string]int64{DeveloperActivationCollection: 0, DeveloperHandleCollection: 1, DeveloperApplicationAuditCollection: 1} {
		n, e := db.Collection(collection).CountDocuments(t.Context(), bson.M{})
		if e != nil || n != want {
			t.Fatal(collection, n, e)
		}
	}
	// Successful historical claims remain idempotent when recovery later closes.
	state, e = r.Evaluate(t.Context(), s.TokenDigest, closed)
	if e != nil || state.DeveloperHandle != "alice" {
		t.Fatal(state, e)
	}
}
func TestDeveloperHandleMongoDamagedOwnershipNeverBecomesLegacy(t *testing.T) {
	for _, mode := range []string{"missing owner", "owner points elsewhere", "wrong handle", "missing first activation evidence", "missing first audit evidence", "null handle"} {
		t.Run(mode, func(t *testing.T) {
			r, db, s := developerFixture(t)
			if _, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply); e != nil {
				t.Fatal(e)
			}
			var e error
			switch mode {
			case "missing owner":
				_, e = db.Collection(DeveloperHandleCollection).DeleteMany(t.Context(), bson.M{})
			case "owner points elsewhere":
				_, e = db.Collection(DeveloperHandleCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"authId": "other-account"}})
			case "wrong handle":
				_, e = db.Collection(DeveloperHandleCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"developerHandle": "other"}})
			case "null handle":
				_, e = db.Collection(DeveloperHandleCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"developerHandle": nil}})
			case "missing first activation evidence":
				_, e = db.Collection(DeveloperActivationCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$unset": bson.M{"developerHandle": ""}})
			case "missing first audit evidence":
				_, e = db.Collection(DeveloperApplicationAuditCollection).UpdateOne(t.Context(), bson.M{"subjectAuthId": s.AuthID}, bson.M{"$unset": bson.M{"developerHandle": ""}})
			}
			if e != nil {
				t.Fatal(e)
			}
			if mode == "missing owner" {
				other := developerAdditionalUser(t, db)
				if _, e = r.Evaluate(t.Context(), other.TokenDigest, developerApplyName("ALICE")); !errors.Is(e, d.ErrApplicationUnavailable) {
					t.Fatal("damaged historical ownership released the name to another account", e)
				}
			}
			for _, action := range []func(d.ApplicationState) (d.HandleClaim, error){developerRead, developerApplyName("NewName")} {
				if _, e = r.Evaluate(t.Context(), s.TokenDigest, action); !errors.Is(e, d.ErrApplicationUnavailable) {
					t.Fatal(mode, e)
				}
			}
		})
	}
	t.Run("legacy claim owner deleted", func(t *testing.T) {
		r, db, s := developerFixture(t)
		if _, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"developerStatus": "APPROVED"}}); e != nil {
			t.Fatal(e)
		}
		if _, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply); e != nil {
			t.Fatal(e)
		}
		if _, e := db.Collection(DeveloperHandleCollection).DeleteMany(t.Context(), bson.M{}); e != nil {
			t.Fatal(e)
		}
		if _, e := r.Evaluate(t.Context(), s.TokenDigest, developerApplyName("NewName")); !errors.Is(e, d.ErrApplicationUnavailable) {
			t.Fatal(e)
		}
	})
}
func TestDeveloperHandleMongoUnrelatedDuplicateAndMigrationConflict(t *testing.T) {
	t.Run("unrelated unique constraint", func(t *testing.T) {
		r, db, first := developerFixture(t)
		second := developerAdditionalUser(t, db)
		if _, e := db.Collection(DeveloperHandleCollection).Indexes().CreateOne(t.Context(), m.IndexModel{Keys: bson.D{{Key: "unrelated", Value: 1}}, Options: options.Index().SetUnique(true)}); e != nil {
			t.Fatal(e)
		}
		if _, e := r.Evaluate(t.Context(), first.TokenDigest, developerApplyName("Alice")); e != nil {
			t.Fatal(e)
		}
		if _, e := r.Evaluate(t.Context(), second.TokenDigest, developerApplyName("Bob")); !errors.Is(e, d.ErrApplicationUnavailable) {
			t.Fatal("unrelated duplicate was reported as name taken", e)
		}
		state, e := r.Evaluate(t.Context(), second.TokenDigest, developerRead)
		if e != nil || state.Status != "" || state.DeveloperHandle != "" {
			t.Fatal(state, e)
		}
	})
	t.Run("migration failure retains old constraint", func(t *testing.T) {
		_, db, _ := developerFixture(t)
		audit := db.Collection(DeveloperApplicationAuditCollection)
		if e := audit.Indexes().DropOne(t.Context(), "developer_subject_action_unique"); e != nil {
			t.Fatal(e)
		}
		if _, e := audit.Indexes().CreateOne(t.Context(), m.IndexModel{Keys: bson.D{{Key: "subjectAuthId", Value: 1}}, Options: options.Index().SetUnique(true)}); e != nil {
			t.Fatal(e)
		}
		if _, e := audit.Indexes().CreateOne(t.Context(), m.IndexModel{Keys: bson.D{{Key: "subjectAuthId", Value: 1}, {Key: "action", Value: 1}}, Options: options.Index().SetName("developer_subject_action_unique")}); e != nil {
			t.Fatal(e)
		}
		if e := EnsureDeveloperApplicationSchema(t.Context(), db); e == nil {
			t.Fatal("conflicting replacement index accepted")
		}
		if e := audit.Indexes().DropOne(t.Context(), "subjectAuthId_1"); e != nil {
			t.Fatal("old protection removed before replacement", e)
		}
	})
}
func TestDeveloperHandleDuplicateClassification(t *testing.T) {
	for _, tc := range []struct {
		key, value string
		code       int
		want       bool
	}{{"developerHandle", "alice", 11000, true}, {"authId", "alice", 11000, false}, {"developerHandle", "bob", 11000, false}, {"developerHandle", "alice", 50, false}} {
		raw, e := bson.Marshal(bson.M{"keyPattern": bson.M{tc.key: 1}, "keyValue": bson.M{tc.key: tc.value}})
		if e != nil {
			t.Fatal(e)
		}
		err := m.WriteException{WriteErrors: m.WriteErrors{{Code: tc.code, Raw: raw}}}
		if got := duplicateDeveloperHandle(err, "alice"); got != tc.want {
			t.Fatal(tc, got)
		}
	}
	if duplicateDeveloperHandle(context.DeadlineExceeded, "alice") {
		t.Fatal("timeout classified as conflict")
	}
}

func TestDeveloperHandleMongoConstraintIdentityAndClaimRollback(t *testing.T) {
	t.Run("real unique constraint identity", func(t *testing.T) {
		_, db, _ := developerFixture(t)
		c := db.Collection(DeveloperHandleCollection)
		first := bson.M{"authId": "one", "developerHandle": "alice", "claimedAt": time.Now(), "eventId": "one"}
		if _, e := c.InsertOne(t.Context(), first); e != nil {
			t.Fatal(e)
		}
		_, e := c.InsertOne(t.Context(), bson.M{"authId": "two", "developerHandle": "alice", "claimedAt": time.Now(), "eventId": "two"})
		if !duplicateDeveloperHandle(e, "alice") {
			t.Fatalf("exact handle conflict not classified: %T %v", e, e)
		}
		_, e = c.InsertOne(t.Context(), bson.M{"authId": "one", "developerHandle": "bob", "claimedAt": time.Now(), "eventId": "three"})
		if e == nil || duplicateDeveloperHandle(e, "bob") {
			t.Fatal("authId constraint confused with handle", e)
		}
	})
	t.Run("historical claim audit rollback", func(t *testing.T) {
		r, db, s := developerFixture(t)
		if _, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": s.AuthID}, bson.M{"$set": bson.M{"developerStatus": "APPROVED"}}); e != nil {
			t.Fatal(e)
		}
		if e := db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: DeveloperApplicationAuditCollection}, {Key: "validator", Value: bson.M{"neverPresent": bson.M{"$exists": true}}}}).Err(); e != nil {
			t.Fatal(e)
		}
		if _, e := r.Evaluate(t.Context(), s.TokenDigest, developerApply); !errors.Is(e, d.ErrApplicationUnavailable) {
			t.Fatal(e)
		}
		state, e := r.Evaluate(t.Context(), s.TokenDigest, developerRead)
		if e != nil || state.Status != d.DeveloperStatusApproved || state.DeveloperHandle != "" || state.ActivatedAt != nil {
			t.Fatal(state, e)
		}
		n, e := db.Collection(DeveloperHandleCollection).CountDocuments(t.Context(), bson.M{})
		if e != nil || n != 0 {
			t.Fatal("failed audit reserved handle", n, e)
		}
		if e := db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: DeveloperApplicationAuditCollection}, {Key: "validator", Value: bson.M{}}}).Err(); e != nil {
			t.Fatal(e)
		}
		state, e = r.Evaluate(t.Context(), s.TokenDigest, developerApply)
		if e != nil || state.DeveloperHandle != "alice" || state.ActivatedAt != nil {
			t.Fatal(state, e)
		}
	})
}
