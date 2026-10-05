package mongo

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/sessionmanagement/domain"
)

func managementFixture(t *testing.T) (*SessionManagementRepository, *m.Database, SessionDocument, SessionDocument, time.Time) {
	t.Helper()
	a, db, current, other := sessionRevocationFixture(t)
	if e := EnsureSessionManagementSchema(t.Context(), db); e != nil {
		t.Fatal(e)
	}
	r, e := NewSessionManagementRepository(a)
	if e != nil {
		t.Fatal(e)
	}
	now := current.CreatedAt.Add(time.Minute)
	a.clock = func() time.Time { return now }
	return r, db, current, other, now
}
func managementID(t *testing.T) string {
	t.Helper()
	p, _ := deviceprotocol.New("test")
	v, e := p.NewID()
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func managementClone(t *testing.T, db *m.Database, base SessionDocument, edit func(*SessionDocument)) SessionDocument {
	t.Helper()
	p, _ := deviceprotocol.New("test")
	base.SessionID = managementID(t)
	_, base.TokenDigest, _ = p.NewSessionToken()
	if edit != nil {
		edit(&base)
	}
	if _, e := db.Collection(SessionCollection).InsertOne(t.Context(), base); e != nil {
		t.Fatal(e)
	}
	return base
}
func managementRead(t *testing.T, db *m.Database, id string) SessionDocument {
	t.Helper()
	var s SessionDocument
	if e := db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": id}).Decode(&s); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestSessionManagementMongoListSourcesIsolationAndNoTouch(t *testing.T) {
	r, db, current, other, now := managementFixture(t)
	email := managementClone(t, db, other, func(s *SessionDocument) { s.AuthenticationMethod = "EMAIL_CODE_AND_DEVICE"; s.EmailBindingRevision = 7 })
	// Email authentication is a historical snapshot, independent of current binding.
	expired := managementClone(t, db, other, func(s *SessionDocument) { s.ExpiresAt = now.Add(-time.Second) })
	revoked := managementClone(t, db, other, func(s *SessionDocument) { s.RevokedAt = &now })
	old := managementClone(t, db, other, func(s *SessionDocument) { s.AccountRevision = 2 })
	foreign := managementClone(t, db, other, func(s *SessionDocument) { s.AuthID = "same-association-other-account" })
	for _, id := range []string{current.AuthID, foreign.AuthID} {
		if _, e := db.Collection("auth_student_association_memberships").InsertOne(t.Context(), bson.M{"authId": id, "associationId": "same-group"}); e != nil {
			t.Fatal(e)
		}
	}
	for _, caller := range []SessionDocument{current, email} {
		page, e := r.List(t.Context(), caller.TokenDigest, 50, "", now)
		if e != nil {
			t.Fatal(e)
		}
		if page.CurrentSessionID != caller.SessionID || !page.ObservedAt.Equal(now) || len(page.Sessions) != 3 || page.NextCursor != "" {
			t.Fatalf("bad page %+v", page)
		}
		actual := map[string]d.Summary{}
		for _, s := range page.Sessions {
			actual[s.SessionID] = s
			if s.IsCurrent != (s.SessionID == caller.SessionID) {
				t.Fatal("bad current flag")
			}
		}
		if actual[email.SessionID].AuthenticationMethod != "EMAIL_CODE_AND_DEVICE" {
			t.Fatal("email source missing")
		}
		for _, id := range []string{expired.SessionID, revoked.SessionID, old.SessionID, foreign.SessionID} {
			if _, ok := actual[id]; ok {
				t.Fatalf("invalid session leaked %s", id)
			}
		}
	}
	for _, original := range []SessionDocument{current, other, email, expired, revoked, old, foreign} {
		got := managementRead(t, db, original.SessionID)
		if !got.LastUsedAt.Equal(original.LastUsedAt) || !got.ExpiresAt.Equal(original.ExpiresAt) {
			t.Fatal("list touched time")
		}
	}
	count, e := db.Collection(SessionManagementAuditCollection).CountDocuments(t.Context(), bson.M{})
	if e != nil || count != 0 {
		t.Fatal("list wrote audit", e)
	}
}
func TestSessionManagementMongoKeysetAndBoundedEmptyPage(t *testing.T) {
	r, db, current, other, now := managementFixture(t)
	// The newest 200 candidates are expired, leaving a valid older page.
	for i := 0; i < 200; i++ {
		managementClone(t, db, current, func(s *SessionDocument) {
			s.CreatedAt = current.CreatedAt.Add(time.Duration(i+1) * time.Millisecond)
			s.AuthenticatedAt = s.CreatedAt
			s.LastUsedAt = s.CreatedAt
			s.ExpiresAt = now.Add(-time.Second)
		})
	}
	page, e := r.List(t.Context(), current.TokenDigest, 1, "", now)
	if e != nil {
		t.Fatal(e)
	}
	if len(page.Sessions) != 0 || page.NextCursor == "" {
		t.Fatalf("expected bounded empty page %+v", page)
	}
	anchor := page.NextCursor
	if _, e = db.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": anchor}, bson.M{"$set": bson.M{"revokedAt": now}}); e != nil {
		t.Fatal(e)
	}
	page, e = r.List(t.Context(), current.TokenDigest, 1, anchor, now)
	if e != nil {
		t.Fatal(e)
	}
	expected := []string{current.SessionID, other.SessionID}
	sort.Sort(sort.Reverse(sort.StringSlice(expected)))
	if len(page.Sessions) != 1 || page.Sessions[0].SessionID != expected[0] || page.NextCursor != expected[0] {
		t.Fatalf("bad ordered page %+v", page)
	}
	last, e := r.List(t.Context(), current.TokenDigest, 1, page.NextCursor, now)
	if e != nil || len(last.Sessions) != 1 || last.Sessions[0].SessionID != expected[1] || last.NextCursor != "" {
		t.Fatalf("bad last page %+v %v", last, e)
	}
	foreign := managementClone(t, db, current, func(s *SessionDocument) { s.AuthID = "foreign" })
	for _, cursor := range []string{managementID(t), foreign.SessionID} {
		if _, e = r.List(t.Context(), current.TokenDigest, 10, cursor, now); !errors.Is(e, d.ErrInvalidCursor) {
			t.Fatalf("foreign/missing cursor: %v", e)
		}
	}
	if _, e = db.Collection(SessionCollection).DeleteOne(t.Context(), bson.M{"sessionId": anchor}); e != nil {
		t.Fatal(e)
	}
	if _, e = r.List(t.Context(), current.TokenDigest, 10, anchor, now); !errors.Is(e, d.ErrInvalidCursor) {
		t.Fatal(e)
	}
}
func TestSessionManagementMongoRevokeAtomicIdempotentAndIsolation(t *testing.T) {
	r, db, current, other, now := managementFixture(t)
	expired := managementClone(t, db, other, func(s *SessionDocument) { s.ExpiresAt = now.Add(-time.Second) })
	foreign := managementClone(t, db, other, func(s *SessionDocument) { s.AuthID = "foreign" })
	targets := []string{other.SessionID, expired.SessionID, foreign.SessionID, managementID(t)}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- r.Revoke(t.Context(), current.TokenDigest, targets, managementID(t), now)
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, id := range []string{other.SessionID, expired.SessionID} {
		got := managementRead(t, db, id)
		if got.RevokedAt == nil || !got.RevokedAt.Equal(now) {
			t.Fatal("not revoked")
		}
	}
	if e := r.Revoke(t.Context(), current.TokenDigest, targets, managementID(t), now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if !managementRead(t, db, other.SessionID).RevokedAt.Equal(now) || managementRead(t, db, foreign.SessionID).RevokedAt != nil || managementRead(t, db, current.SessionID).RevokedAt != nil {
		t.Fatal("revocation broadened/changed")
	}
	var audit struct {
		Action, ActorAuthID, ActorSessionID string
		SessionIDs                          []string  `bson:"sessionIds"`
		OccurredAt                          time.Time `bson:"occurredAt"`
	}
	var raw bson.M
	if e := db.Collection(SessionManagementAuditCollection).FindOne(t.Context(), bson.M{}).Decode(&raw); e != nil {
		t.Fatal(e)
	}
	if raw["actorAuthId"] != current.AuthID || raw["actorSessionId"] != current.SessionID || raw["action"] != "REVOKE_OWN_SESSIONS" {
		t.Fatal(raw)
	}
	if e := db.Collection(SessionManagementAuditCollection).FindOne(t.Context(), bson.M{}).Decode(&audit); e != nil {
		t.Fatal(e)
	}
	if len(audit.SessionIDs) != 2 {
		t.Fatal(audit)
	}
	count, e := db.Collection(SessionManagementAuditCollection).CountDocuments(t.Context(), bson.M{})
	if e != nil || count != 1 {
		t.Fatal("duplicate audit", count, e)
	}
	if _, e = r.auth.CheckSession(t.Context(), other.TokenDigest, now); !errors.Is(e, auth.ErrSessionInvalid) {
		t.Fatal("revoked online check", e)
	}
	// An explicit retry cannot revoke a later session on the same credential.
	fresh := managementClone(t, db, current, nil)
	if e = r.Revoke(t.Context(), current.TokenDigest, targets, managementID(t), now); e != nil {
		t.Fatal(e)
	}
	if _, e = r.auth.CheckSession(t.Context(), fresh.TokenDigest, now); e != nil {
		t.Fatal("fresh session affected", e)
	}
	if !managementRead(t, db, current.SessionID).LastUsedAt.Equal(current.LastUsedAt) {
		t.Fatal("revoke touched caller")
	}
}
func TestSessionManagementMongoRejectCurrentAndAuditRollback(t *testing.T) {
	r, db, current, other, now := managementFixture(t)
	if e := r.Revoke(t.Context(), current.TokenDigest, []string{other.SessionID, current.SessionID}, managementID(t), now); !errors.Is(e, d.ErrCurrentSession) {
		t.Fatal(e)
	}
	if managementRead(t, db, other.SessionID).RevokedAt != nil {
		t.Fatal("partial mutation")
	}
	event := managementID(t)
	if _, e := db.Collection(SessionManagementAuditCollection).InsertOne(t.Context(), bson.M{"eventId": event}); e != nil {
		t.Fatal(e)
	}
	if e := r.Revoke(t.Context(), current.TokenDigest, []string{other.SessionID}, event, now); !errors.Is(e, d.ErrUnavailable) {
		t.Fatal(e)
	}
	if managementRead(t, db, other.SessionID).RevokedAt != nil {
		t.Fatal("audit failure leaked mutation")
	}
	if e := r.auth.RevokeCurrentSession(t.Context(), current.TokenDigest, now); e != nil {
		t.Fatal(e)
	}
	if e := r.Revoke(t.Context(), current.TokenDigest, []string{other.SessionID}, managementID(t), now); !errors.Is(e, d.ErrSessionInvalid) {
		t.Fatal(e)
	}
}
func TestSessionManagementMongoInvalidAndCorruptSources(t *testing.T) {
	tests := []struct {
		name         string
		collection   string
		update       bson.M
		invalid      bool
		targetCaller bool
	}{
		{"old generation", SessionCollection, bson.M{"$set": bson.M{"accountRevision": int64(2)}}, true, true},
		{"missing revision", SessionCollection, bson.M{"$unset": bson.M{"accountRevision": ""}}, false, false},
		{"wrong revision type", SessionCollection, bson.M{"$set": bson.M{"accountRevision": int32(1)}}, false, true},
		{"unknown authentication", SessionCollection, bson.M{"$set": bson.M{"authenticationMethod": "OTHER"}}, false, false},
		{"email malformed", SessionCollection, bson.M{"$set": bson.M{"authenticationMethod": "EMAIL_CODE_AND_DEVICE", "emailBindingRevision": int32(1)}}, false, false},
		{"device unexpected email", SessionCollection, bson.M{"$set": bson.M{"emailBindingRevision": int64(1)}}, false, false},
		{"missing credential", SessionCollection, bson.M{"$set": bson.M{"credentialId": "99999999-9999-4999-8999-999999999999"}}, false, false},
		{"credential owner", CredentialCollection, bson.M{"$set": bson.M{"authId": "foreign"}}, false, true},
		{"credential public key", CredentialCollection, bson.M{"$set": bson.M{"publicKey": []byte{1}}}, false, true},
		{"disabled", PrincipalCollection, bson.M{"$set": bson.M{"accountStatus": "DISABLED", "accountRevision": int64(2)}}, true, true},
		{"closed", PrincipalCollection, bson.M{"$set": bson.M{"accountStatus": "CLOSED", "accountRevision": int64(2)}}, true, true},
		{"restored", PrincipalCollection, bson.M{"$set": bson.M{"accountStatus": "ACTIVE", "accountRevision": int64(3)}}, true, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, db, current, other, now := managementFixture(t)
			target := other
			if test.targetCaller {
				target = current
			}
			filter := bson.M{"sessionId": target.SessionID}
			if test.collection == CredentialCollection {
				filter = bson.M{"credentialId": target.CredentialID}
			}
			if test.collection == PrincipalCollection {
				filter = bson.M{"authId": target.AuthID}
			}
			if _, e := db.Collection(test.collection).UpdateOne(t.Context(), filter, test.update); e != nil {
				t.Fatal(e)
			}
			_, e := r.List(t.Context(), current.TokenDigest, 50, "", now)
			expected := d.ErrUnavailable
			if test.invalid {
				expected = d.ErrSessionInvalid
			}
			if !errors.Is(e, expected) {
				t.Fatalf("got %v expected %v", e, expected)
			}
		})
	}
}
func TestSessionManagementMongoRevokedCredentialFilteredAndCallerRejected(t *testing.T) {
	r, db, current, other, now := managementFixture(t)
	// Give other a distinct, structurally valid revoked credential.
	var c CredentialDocument
	if e := db.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": other.CredentialID}).Decode(&c); e != nil {
		t.Fatal(e)
	}
	c.CredentialID = managementID(t)
	c.RevokedAt = &now
	// fingerprint is uniquely indexed: use a fixture from another isolated database.
	_, db2, s2, _, _ := managementFixture(t)
	var c2 CredentialDocument
	if e := db2.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": s2.CredentialID}).Decode(&c2); e != nil {
		t.Fatal(e)
	}
	c.PublicKey = c2.PublicKey
	c.Fingerprint = c2.Fingerprint
	if _, e := db.Collection(CredentialCollection).InsertOne(t.Context(), c); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": other.SessionID}, bson.M{"$set": bson.M{"credentialId": c.CredentialID}}); e != nil {
		t.Fatal(e)
	}
	page, e := r.List(t.Context(), current.TokenDigest, 50, "", now)
	if e != nil || len(page.Sessions) != 1 {
		t.Fatal(page, e)
	}
	if _, e = r.List(t.Context(), other.TokenDigest, 50, "", now); !errors.Is(e, d.ErrSessionInvalid) {
		t.Fatal(e)
	}
	if e = r.Revoke(t.Context(), current.TokenDigest, []string{other.SessionID}, managementID(t), now); e != nil {
		t.Fatal(e)
	}
	var before, after bson.Raw
	if e = db.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": c.CredentialID}).Decode(&before); e != nil {
		t.Fatal(e)
	}
	if e = r.Revoke(t.Context(), current.TokenDigest, []string{other.SessionID}, managementID(t), now); e != nil {
		t.Fatal(e)
	}
	if e = db.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": c.CredentialID}).Decode(&after); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("revocation changed target credential")
	}
}

func TestSessionManagementMongoTransientRetryAndUnknownCommit(t *testing.T) {
	_, db, current, other, now := managementFixture(t)
	a, name := sessionRevocationFaultRepository(t, db)
	a.clock = func() time.Time { return now }
	r, _ := NewSessionManagementRepository(a)
	admin := db.Client().Database("admin")
	disable := func() {
		_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	}
	t.Cleanup(disable)
	// Fail the audit insert after all target writes, force a complete callback retry.
	if e := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: bson.M{"times": 1}}, {Key: "data", Value: bson.M{"appName": name, "failCommands": bson.A{"insert"}, "errorCode": 112, "errorLabels": bson.A{"TransientTransactionError"}}}}).Err(); e != nil {
		t.Fatal(e)
	}
	event := managementID(t)
	if e := r.Revoke(t.Context(), current.TokenDigest, []string{other.SessionID}, event, now); e != nil {
		t.Fatal("transient retry", e)
	}
	count, e := db.Collection(SessionManagementAuditCollection).CountDocuments(t.Context(), bson.M{"eventId": event})
	if e != nil || count != 1 {
		t.Fatal("retry audit", count, e)
	}
	fresh := managementClone(t, db, other, nil)
	if e = admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": name, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if e = r.Revoke(ctx, current.TokenDigest, []string{fresh.SessionID}, managementID(t), now); !errors.Is(e, d.ErrUnavailable) {
		t.Fatal("unknown commit claimed success", e)
	}
	disable()
	if e = r.Revoke(t.Context(), current.TokenDigest, []string{fresh.SessionID}, managementID(t), now); e != nil {
		t.Fatal("explicit retry", e)
	}
}
func TestSessionManagementMongoConcurrentCallerRevocationSerializes(t *testing.T) {
	r, db, current, other, now := managementFixture(t)
	start := make(chan struct{})
	result := make(chan error, 2)
	go func() {
		<-start
		result <- r.Revoke(t.Context(), current.TokenDigest, []string{other.SessionID}, managementID(t), now)
	}()
	go func() { <-start; result <- r.auth.RevokeCurrentSession(t.Context(), current.TokenDigest, now) }()
	close(start)
	for range 2 {
		e := <-result
		if e != nil && !errors.Is(e, d.ErrSessionInvalid) {
			t.Fatal(e)
		}
	}
	if managementRead(t, db, current.SessionID).RevokedAt == nil {
		t.Fatal("caller revocation lost")
	}
	if e := r.Revoke(t.Context(), current.TokenDigest, []string{other.SessionID}, managementID(t), now); !errors.Is(e, d.ErrSessionInvalid) {
		t.Fatal("post revoke management", e)
	}
}
func TestSessionManagementMongoLoginLRURaceAndReauthentication(t *testing.T) {
	f := newAuthenticationFixture(t)
	db := f.r.database
	if e := EnsureSessionManagementSchema(t.Context(), db); e != nil {
		t.Fatal(e)
	}
	r, _ := NewSessionManagementRepository(f.r)
	first := f.login(t)
	for range 8 {
		f.login(t)
	}
	caller := f.login(t)
	digest, e := f.p.TokenDigest(caller.SessionToken)
	if e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		<-start
		result <- r.Revoke(t.Context(), digest, []string{first.SessionID}, managementID(t), time.Now())
	}()
	go func() { <-start; defer close(done); f.login(t) }()
	close(start)
	if e = <-result; e != nil {
		t.Fatal(e)
	}
	<-done
	removed := managementRead(t, db, first.SessionID)
	if removed.RevokedAt == nil {
		t.Fatal("LRU/revoke lost")
	}
	if _, e = f.u.Check(t.Context(), first.SessionToken); !errors.Is(e, auth.ErrSessionInvalid) {
		t.Fatal("old token valid", e)
	}
	fresh := f.login(t)
	if e = r.Revoke(t.Context(), digest, []string{first.SessionID}, managementID(t), time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = f.u.Check(t.Context(), fresh.SessionToken); e != nil {
		t.Fatal("same credential reauthentication blocked", e)
	}
	if !managementRead(t, db, first.SessionID).RevokedAt.Equal(*removed.RevokedAt) {
		t.Fatal("first timestamp changed")
	}
	count, e := db.Collection(SessionCollection).CountDocuments(t.Context(), bson.M{"authId": caller.AuthID, "revokedAt": nil})
	if e != nil || count != 10 {
		t.Fatal("capacity", count, e)
	}
}
func TestSessionManagementMongoAuditRetentionOnlyClosedAfter180Days(t *testing.T) {
	f := newClosureFixture(t)
	if e := EnsureSessionManagementSchema(t.Context(), f.repo.auth.database); e != nil {
		t.Fatal(e)
	}
	p := f.ready(t)
	f.close(t, p)
	f.acknowledge(t, p.OperationID)
	f.drain(t)
	closureInsert(t, f, PrincipalCollection, bson.M{"authId": "active-audit-owner", "accountStatus": "ACTIVE"})
	for _, v := range []struct {
		id, owner string
		at        time.Time
	}{
		{"closed-old", f.c.AuthID, f.clock}, {"active-old", "active-audit-owner", f.clock}, {"closed-young", f.c.AuthID, f.clock.Add(2 * 24 * time.Hour)},
	} {
		closureInsert(t, f, SessionManagementAuditCollection, bson.M{"eventId": v.id, "actorAuthId": v.owner, "occurredAt": v.at})
	}
	if e := f.repo.Retain(t.Context(), f.clock.Add(181*24*time.Hour), 500); e != nil {
		t.Fatal(e)
	}
	if closureCount(t, f, SessionManagementAuditCollection, bson.M{"eventId": "closed-old"}) != 0 || closureCount(t, f, SessionManagementAuditCollection, bson.M{}) != 2 {
		t.Fatal("audit retention affected wrong subject/age")
	}
}
