package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	cd "iwut-auth-center/internal/accountclosure/domain"
	cp "iwut-auth-center/internal/accountclosure/port"
	cu "iwut-auth-center/internal/accountclosure/usecase"
	"iwut-auth-center/internal/adapter/closureprotocol"
	"iwut-auth-center/internal/adapter/terminationledger"
	ap "iwut-auth-center/internal/authentication/port"
	developer "iwut-auth-center/internal/developer/domain"
	owner "iwut-auth-center/internal/ownerexit/domain"
	"os"
	"testing"
	"time"
)

// This fixture isolates repository fault cases. Wire's dual-service acceptance
// separately exercises the production App provider and persistent App receipt.
type closureAppStub struct {
	receipt string
	blocked string
	fail    bool
}

func (a *closureAppStub) Prepare(_ context.Context, o owner.Operation) (owner.Preparation, error) {
	if a.fail {
		return owner.Preparation{}, errors.New("network")
	}
	return owner.Preparation{ReceiptID: a.receipt, Blocker: a.blocked}, nil
}
func (a *closureAppStub) Finish(_ context.Context, o owner.Operation) (owner.Status, error) {
	return owner.Status{AuthID: o.AuthID, OperationID: o.OperationID, Purpose: o.Purpose, Decision: o.Decision, ReceiptID: o.ReceiptID, CleanupState: "COMPLETE"}, nil
}
func (a *closureAppStub) Status(_ context.Context, o owner.Operation) (owner.Status, error) {
	return owner.Status{AuthID: o.AuthID, OperationID: o.OperationID, Purpose: owner.Closure, Decision: owner.Committed, ReceiptID: a.receipt, CleanupState: "COMPLETE"}, nil
}

type closureLedgerFault struct {
	cp.TerminationLedger
	fail bool
}

func (l *closureLedgerFault) Store(ctx context.Context, t cd.Termination) error {
	if l.fail {
		return errors.New("disk unavailable")
	}
	return l.TerminationLedger.Store(ctx, t)
}

type closureFixture struct {
	authenticationFixture
	repo    *AccountClosureRepository
	service *cu.Service
	app     *closureAppStub
	ledger  *closureLedgerFault
	clock   time.Time
}

func newClosureFixture(t *testing.T) *closureFixture {
	t.Helper()
	a := newAuthenticationFixture(t)
	return buildClosureFixture(t, a)
}
func buildClosureFixture(t *testing.T, a authenticationFixture) *closureFixture {
	t.Helper()
	db := a.r.database
	for _, e := range []error{EnsureAccountClosureSchema(t.Context(), db), EnsureOwnerExitSchema(t.Context(), db), EnsureAssociationSchema(t.Context(), db)} {
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": a.c.AuthID}, bson.M{"$set": bson.M{"developerRevision": int64(0), "permissionRevision": int64(1), "permissions": bson.A{}, "developerStatus": nil, "profile": bson.M{"name": "student"}}})
	if e != nil {
		t.Fatal(e)
	}
	repo, e := NewAccountClosureRepository(a.r)
	if e != nil {
		t.Fatal(e)
	}
	p, e := closureprotocol.New("iwut-auth-center:test")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	ledger, e := terminationledger.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	id, e := uuid.NewV7()
	if e != nil {
		t.Fatal(e)
	}
	f := &closureFixture{authenticationFixture: a, repo: repo, app: &closureAppStub{receipt: id.String()}, ledger: &closureLedgerFault{TerminationLedger: ledger}, clock: time.Now().UTC().Truncate(time.Millisecond)}
	f.service, e = cu.New(repo, p, f.app, NewOwnerExitRepository(a.r), f.ledger, "iwut-auth-center:test")
	if e != nil {
		t.Fatal(e)
	}
	f.service.SetClock(func() time.Time { return f.clock })
	return f
}
func (f *closureFixture) begin(t *testing.T) cd.Challenge {
	t.Helper()
	c, e := f.service.Begin(t.Context(), cd.BeginInput{RequestID: uuid.NewString(), CredentialID: f.c.CredentialID})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func (f *closureFixture) ready(t *testing.T) cd.Preparation {
	t.Helper()
	c := f.begin(t)
	p, e := f.service.Prepare(t.Context(), c.OperationID, signAuthentication(t, f.key, c.SigningPayload))
	if e != nil || p.Outcome != "READY" {
		t.Fatalf("prepare=%+v err=%v", p, e)
	}
	return p
}
func (f *closureFixture) close(t *testing.T, p cd.Preparation) cd.Status {
	t.Helper()
	s, e := f.service.Confirm(t.Context(), p.OperationID, p.ConfirmationToken, "CLOSE_ACCOUNT", cd.PolicyVersion)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func (f *closureFixture) acknowledge(t *testing.T, id string) {
	t.Helper()
	r := NewOwnerExitRepository(f.r)
	op, e := r.Get(t.Context(), f.c.AuthID, id)
	if e != nil {
		t.Fatal(e)
	}
	status, e := f.app.Finish(t.Context(), op)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Acknowledge(t.Context(), op, status, f.clock); e != nil {
		t.Fatal(e)
	}
}
func (f *closureFixture) drain(t *testing.T) {
	t.Helper()
	for i := 0; i < 60; i++ {
		if e := f.service.Tick(t.Context()); e != nil {
			t.Fatal(e)
		}
		pending, e := f.repo.Pending(t.Context(), f.clock, 500)
		if e != nil {
			t.Fatal(e)
		}
		if len(pending) == 0 {
			return
		}
	}
	t.Fatal("cleanup did not drain")
}
func closureInsert(t *testing.T, f *closureFixture, col string, doc any) {
	t.Helper()
	if _, e := f.r.database.Collection(col).InsertOne(t.Context(), doc); e != nil {
		t.Fatal(e)
	}
}
func closureCount(t *testing.T, f *closureFixture, col string, q bson.M) int64 {
	t.Helper()
	n, e := f.r.database.Collection(col).CountDocuments(t.Context(), q)
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func TestAccountClosureProofDisabledAndSecretIsolation(t *testing.T) {
	for _, state := range []string{"ACTIVE", "DISABLED"} {
		t.Run(state, func(t *testing.T) {
			f := newClosureFixture(t)
			_, e := f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"accountStatus": state}})
			if e != nil {
				t.Fatal(e)
			}
			if state == "DISABLED" {
				c := f.authenticationFixture.begin(t)
				if _, e = f.u.Complete(t.Context(), c.OperationID, signAuthentication(t, f.key, c.SigningPayload)); !errors.Is(e, ap.ErrAuthenticationFailed) {
					t.Fatalf("disabled login=%v", e)
				}
			}
			p := f.ready(t)
			if _, e = f.service.Confirm(t.Context(), p.OperationID, p.ReceiptToken, "CLOSE_ACCOUNT", cd.PolicyVersion); !errors.Is(e, cd.ErrToken) {
				t.Fatalf("receipt confirmed=%v", e)
			}
			if _, e = f.service.Get(t.Context(), p.OperationID, p.ConfirmationToken); !errors.Is(e, cd.ErrToken) {
				t.Fatalf("confirmation read=%v", e)
			}
			s := f.close(t, p)
			if s.State != cd.Terminated {
				t.Fatal(s)
			}
			again := f.close(t, p)
			if again.State != cd.Terminated {
				t.Fatal(again)
			}
			var doc bson.M
			if e = f.r.database.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": f.c.AuthID}).Decode(&doc); e != nil {
				t.Fatal(e)
			}
			if len(doc) != 7 || doc["accountRevision"] != int64(2) || doc["accountStatus"] != "CLOSED" {
				t.Fatalf("tombstone=%v", doc)
			}
			if _, e = f.service.Cancel(t.Context(), p.OperationID, p.ConfirmationToken); !errors.Is(e, cd.ErrConflict) {
				t.Fatalf("cancel committed=%v", e)
			}
		})
	}
}
func TestAccountClosureUnknownProofAndRequestDedup(t *testing.T) {
	f := newClosureFixture(t)
	in := cd.BeginInput{RequestID: uuid.NewString(), CredentialID: uuid.NewString()}
	a, e := f.service.Begin(t.Context(), in)
	if e != nil {
		t.Fatal(e)
	}
	b, e := f.service.Begin(t.Context(), in)
	if e != nil || a.OperationID != b.OperationID || !a.ExpiresAt.Equal(b.ExpiresAt) {
		t.Fatal("dedup changed challenge")
	}
	in.CredentialID = f.c.CredentialID
	if _, e = f.service.Begin(t.Context(), in); !errors.Is(e, cd.ErrConflict) {
		t.Fatal(e)
	}
	for i := 0; i < 6; i++ {
		if _, e = f.service.Prepare(t.Context(), a.OperationID, signAuthentication(t, f.key, a.SigningPayload)); !errors.Is(e, cd.ErrProof) {
			t.Fatal(e)
		}
	}
	o, e := f.repo.Read(t.Context(), a.OperationID)
	if e != nil || o.FailedAttempts != 5 {
		t.Fatalf("attempts=%d err=%v", o.FailedAttempts, e)
	}
	c := f.begin(t)
	ordinary := f.authenticationFixture.begin(t)
	if _, e = f.service.Prepare(t.Context(), c.OperationID, signAuthentication(t, f.key, ordinary.SigningPayload)); !errors.Is(e, cd.ErrProof) {
		t.Fatalf("login signature accepted=%v", e)
	}
}
func TestAccountClosurePreviewChangesInvalidate(t *testing.T) {
	for _, change := range []string{"email", "key", "other_key", "permission", "developer", "account"} {
		t.Run(change, func(t *testing.T) {
			f := newClosureFixture(t)
			p := f.ready(t)
			db := f.r.database
			var e error
			switch change {
			case "email":
				_, e = db.Collection(EmailBindingCollection).InsertOne(t.Context(), bson.M{"authId": f.c.AuthID, "email": "changed@example.com", "revision": int64(1), "verifiedAt": f.clock})
			case "key":
				_, e = db.Collection(CredentialCollection).UpdateOne(t.Context(), bson.M{"credentialId": f.c.CredentialID}, bson.M{"$set": bson.M{"revokedAt": f.clock}})
			case "other_key":
				secondaryCredential(t, f.authenticationFixture, f.c.AuthID)
			case "permission":
				_, e = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"permissionRevision": int64(1)}})
			case "developer":
				_, e = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"developerRevision": int64(1)}})
			case "account":
				_, e = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"accountRevision": int64(1)}})
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.service.Confirm(t.Context(), p.OperationID, p.ConfirmationToken, "CLOSE_ACCOUNT", cd.PolicyVersion); !errors.Is(e, cd.ErrConflict) {
				t.Fatalf("stale preview=%v", e)
			}
			op, e := NewOwnerExitRepository(f.r).Get(t.Context(), f.c.AuthID, p.OperationID)
			if e != nil || op.Decision != owner.Cancelled {
				t.Fatalf("decision=%s err=%v", op.Decision, e)
			}
		})
	}
}
func TestAccountClosureLedgerFailureAndReplayConflict(t *testing.T) {
	f := newClosureFixture(t)
	p := f.ready(t)
	f.ledger.fail = true
	s := f.close(t, p)
	if s.State != cd.TerminationPending {
		t.Fatal(s)
	}
	if _, e := f.service.Cancel(t.Context(), p.OperationID, p.ConfirmationToken); !errors.Is(e, cd.ErrConflict) {
		t.Fatal(e)
	}
	if e := f.service.Reconcile(t.Context()); !errors.Is(e, cd.ErrUnavailable) {
		t.Fatal(e)
	}
	f.ledger.fail = false
	if e := f.service.Reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	records, e := f.ledger.Records(t.Context())
	if e != nil || len(records) != 1 {
		t.Fatal(e)
	}
	for _, rev := range []int64{1, 3} {
		_, e = f.r.database.Collection(PrincipalCollection).ReplaceOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"authId": f.c.AuthID, "principalType": "USER", "accountStatus": "ACTIVE", "accountRevision": rev})
		if e != nil {
			t.Fatal(e)
		}
		e = f.repo.Replay(t.Context(), records[0])
		if rev == 1 && e != nil {
			t.Fatal(e)
		}
		if rev == 3 && !errors.Is(e, cd.ErrUnavailable) {
			t.Fatalf("higher ACTIVE revision bypassed ledger=%v", e)
		}
	}
}
func TestAccountClosureCleanupActualCollectionsAndPermanentOccupancy(t *testing.T) {
	f := newClosureFixture(t)
	auth := f.c.AuthID
	now := f.clock
	closureInsert(t, f, EmailBindingCollection, bson.M{"authId": auth, "email": "old@example.com", "revision": int64(1)})
	closureInsert(t, f, AuthenticationOperationCollection, bson.M{"operationId": "registration-result", "completedAuthId": auth, "status": "COMPLETED"})
	closureInsert(t, f, EmailOperationCollection, bson.M{"operationId": "registration-result", "owner": "fingerprint-owner", "email": "old@example.com"})
	closureInsert(t, f, EmailOperationCollection, bson.M{"operationId": "binding-result", "owner": auth, "email": "old@example.com"})
	closureInsert(t, f, DeveloperHandleCollection, bson.M{"authId": auth, "developerHandle": "permanent", "claimedAt": now, "eventId": "event"})
	closureInsert(t, f, DeveloperActivationCollection, bson.M{"authId": auth, "personalSnapshot": "erase"})
	closureInsert(t, f, AssociationCollection, bson.M{"associationId": "shared", "keyVersion": "v1", "lookupKey": []byte("lookup"), "ciphertext": []byte("encrypted")})
	for _, id := range []string{auth, "other"} {
		closureInsert(t, f, AssociationMemberCollection, bson.M{"authId": id, "associationId": "shared"})
	}
	for _, kind := range []string{"interactions", "codes", "access", "grants", "subjects", "families"} {
		closureInsert(t, f, "auth_oauth_"+kind, bson.M{"_id": kind + "-id", "data": bson.M{"authid": auth, "private": "erase"}})
		closureInsert(t, f, "auth_oauth_"+kind, bson.M{"_id": "other-" + kind, "data": bson.M{"authid": "other"}})
	}
	closureInsert(t, f, "auth_oauth_refresh", bson.M{"_id": "refresh", "data": bson.M{"familyid": "families-id"}})
	f.authenticationFixture.login(t)
	p := f.ready(t)
	f.close(t, p)
	f.acknowledge(t, p.OperationID)
	f.drain(t)
	for _, col := range []string{CredentialCollection, SessionCollection, AuthenticationOperationCollection, EmailOperationCollection, EmailBindingCollection, DeveloperActivationCollection} {
		if n := closureCount(t, f, col, bson.M{}); n != 0 {
			t.Fatalf("%s remains %d", col, n)
		}
	}
	for _, kind := range []string{"interactions", "codes", "access", "grants", "subjects", "families"} {
		if n := closureCount(t, f, "auth_oauth_"+kind, bson.M{}); n != 1 {
			t.Fatalf("%s other ownership count=%d", kind, n)
		}
	}
	if closureCount(t, f, "auth_oauth_refresh", bson.M{}) != 0 || closureCount(t, f, AssociationMemberCollection, bson.M{}) != 1 || closureCount(t, f, AssociationCollection, bson.M{}) != 1 {
		t.Fatal("linked data deletion wrong")
	}
	if closureCount(t, f, CredentialTombstoneCollection, bson.M{"fingerprint": f.c.Fingerprint}) != 1 {
		t.Fatal("missing fingerprint")
	}
	if e := f.r.WithAuthTransaction(t.Context(), func(ctx context.Context) error { return f.r.InsertCredentialTx(ctx, f.c) }); !errors.Is(e, ap.ErrCredentialRegistered) {
		t.Fatalf("reused closed key=%v", e)
	}
	var handle bson.M
	if e := f.r.database.Collection(DeveloperHandleCollection).FindOne(t.Context(), bson.M{"authId": auth}).Decode(&handle); e != nil {
		t.Fatal(e)
	}
	if len(handle) != 5 || handle["terminal"] != true {
		t.Fatalf("handle=%v", handle)
	}
	s, e := f.service.Get(t.Context(), p.OperationID, p.ReceiptToken)
	if e != nil || s.State != cd.CleanupComplete {
		t.Fatalf("status=%v err=%v", s, e)
	}
	// A retry after the released email is claimed by another authId cannot delete it.
	closureInsert(t, f, EmailBindingCollection, bson.M{"authId": "new-owner", "email": "old@example.com", "revision": int64(1)})
	if e = f.service.Tick(t.Context()); e != nil {
		t.Fatal(e)
	}
	if closureCount(t, f, EmailBindingCollection, bson.M{"authId": "new-owner"}) != 1 {
		t.Fatal("deleted new email owner")
	}
}
func TestAccountClosureRestoreReservationsAndRejectWrongLedger(t *testing.T) {
	f := newClosureFixture(t)
	second := secondaryCredential(t, f.authenticationFixture, f.c.AuthID)
	closureInsert(t, f, DeveloperHandleCollection, bson.M{"authId": f.c.AuthID, "developerHandle": "reserved", "claimedAt": f.clock.Add(-time.Hour), "eventId": "event"})
	p := f.ready(t)
	f.close(t, p)
	records, e := f.ledger.Records(t.Context())
	if e != nil || len(records) != 1 {
		t.Fatal(e)
	}
	if e = f.repo.VerifyLedger(t.Context(), nil); !errors.Is(e, cd.ErrUnavailable) {
		t.Fatalf("empty independent ledger accepted=%v", e)
	}
	// An older backup predates the second device and handle claim.
	_, e = f.r.database.Collection(CredentialCollection).DeleteOne(t.Context(), bson.M{"credentialId": second.c.CredentialID})
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.r.database.Collection(DeveloperHandleCollection).DeleteMany(t.Context(), bson.M{})
	if e = f.service.Reconcile(t.Context()); e != nil {
		t.Fatal(e)
	}
	if closureCount(t, f, CredentialTombstoneCollection, bson.M{"fingerprint": second.c.Fingerprint}) != 1 || closureCount(t, f, DeveloperHandleCollection, bson.M{"developerHandle": "reserved", "terminal": true}) != 1 {
		t.Fatal("older backup lost permanent namespace ownership")
	}
	r, _ := NewDeveloperApplicationRepository(f.r)
	if e = r.claimHandle(t.Context(), "someone-new", "reserved", "event-new", f.clock); !errors.Is(e, developer.ErrHandleTaken) {
		t.Fatalf("closed handle result=%v", e)
	}
	names, e := f.ledger.Reservations(t.Context(), records[0].OperationID)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = f.r.database.Collection(CredentialTombstoneCollection).UpdateOne(t.Context(), bson.M{"fingerprint": second.c.Fingerprint}, bson.M{"$set": bson.M{"authId": "conflicting-owner"}})
	if e = f.repo.ReplayReservations(t.Context(), names); !errors.Is(e, cd.ErrUnavailable) {
		t.Fatalf("namespace conflict accepted=%v", e)
	}
}
func TestAccountClosureAssociationWaitsForPendingRegistration(t *testing.T) {
	f := newClosureFixture(t)
	closureInsert(t, f, AssociationCollection, bson.M{"associationId": "pending-shared", "keyVersion": "v1", "lookupKey": []byte("same"), "ciphertext": []byte("sealed")})
	closureInsert(t, f, AssociationMemberCollection, bson.M{"authId": f.c.AuthID, "associationId": "pending-shared"})
	closureInsert(t, f, AuthenticationOperationCollection, bson.M{"operationId": "other-register", "purpose": "REGISTER", "status": "PENDING", "keyVersion": "v1", "lookupKey": []byte("same"), "expiresAt": f.clock.Add(time.Minute)})
	p := f.ready(t)
	f.close(t, p)
	f.acknowledge(t, p.OperationID)
	for i := 0; i < 25; i++ {
		if e := f.service.Tick(t.Context()); e != nil {
			t.Fatal(e)
		}
	}
	s, e := f.service.Get(t.Context(), p.OperationID, p.ReceiptToken)
	if e != nil || s.State == cd.CleanupComplete {
		t.Fatalf("pending reference declared clean=%v %v", s, e)
	}
	if closureCount(t, f, AssociationMemberCollection, bson.M{}) != 0 || closureCount(t, f, AssociationCollection, bson.M{}) != 1 {
		t.Fatal("pending shared group erased or old member retained")
	}
	f.clock = f.clock.Add(2 * time.Minute)
	f.drain(t)
	if closureCount(t, f, AssociationCollection, bson.M{}) != 0 {
		t.Fatal("empty group leaked after pending expiry")
	}
}
func TestAccountClosureCleanupFairnessAndRetention(t *testing.T) {
	f := newClosureFixture(t)
	p := f.ready(t)
	f.close(t, p)
	f.acknowledge(t, p.OperationID)
	f.drain(t)
	future := f.clock.Add(181 * 24 * time.Hour)
	for i := 0; i < 5; i++ {
		closureInsert(t, f, PermissionAuditCollection, bson.M{"eventId": uuid.NewString(), "subjectAuthId": "active", "occurredAt": f.clock.Add(-time.Hour)})
	}
	closureInsert(t, f, PrincipalCollection, bson.M{"authId": "active", "accountStatus": "ACTIVE"})
	closureInsert(t, f, PermissionAuditCollection, bson.M{"eventId": "closed-event", "subjectAuthId": f.c.AuthID, "occurredAt": f.clock.Add(-time.Hour)})
	if e := f.repo.Retain(t.Context(), future, 2); e != nil {
		t.Fatal(e)
	}
	if closureCount(t, f, PermissionAuditCollection, bson.M{"eventId": "closed-event"}) != 0 || closureCount(t, f, PermissionAuditCollection, bson.M{"subjectAuthId": "active"}) != 5 {
		t.Fatal("active audits starved closed retention")
	}
	if _, e := f.service.Get(t.Context(), p.OperationID, p.ReceiptToken); !errors.Is(e, cd.ErrToken) {
		t.Fatalf("expired secret retained=%v", e)
	}
	for i := 0; i < 3; i++ {
		closureInsert(t, f, AccountClosureTaskCollection, bson.M{"operationId": uuid.NewString(), "authId": "blocked", "accountRevision": int64(2), "terminatedAt": f.clock.Add(-time.Hour), "ledgerConfirmed": true, "localComplete": false, "appComplete": false})
	}
	first, e := f.repo.Pending(t.Context(), future, 2)
	if e != nil || len(first) != 2 {
		t.Fatal(e)
	}
	for _, o := range first {
		if e = f.repo.Attempt(t.Context(), o.OperationID, future); e != nil {
			t.Fatal(e)
		}
	}
	next, e := f.repo.Pending(t.Context(), future, 2)
	if e != nil || len(next) != 2 || next[0].OperationID == first[0].OperationID || next[0].OperationID == first[1].OperationID {
		t.Fatalf("pending tasks starved=%v %v", next, e)
	}
}
func TestAccountClosureGovernanceBlocksAndAppObligations(t *testing.T) {
	for _, kind := range []string{"admin", "approved", "suspended", "app"} {
		t.Run(kind, func(t *testing.T) {
			f := newClosureFixture(t)
			change := bson.M{}
			want := ""
			switch kind {
			case "admin":
				change["permissions"] = bson.A{"auth.account.manage"}
				want = cd.AdminBlocker
			case "approved":
				change["developerStatus"] = "APPROVED"
				change["developerRevision"] = int64(1)
				want = cd.DeveloperBlocker
			case "suspended":
				change["developerStatus"] = "SUSPENDED"
				change["developerRevision"] = int64(1)
			case "app":
				f.app.receipt = ""
				f.app.blocked = "OWNED_APPLICATIONS"
				want = f.app.blocked
			}
			if len(change) > 0 {
				if _, e := f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": change}); e != nil {
					t.Fatal(e)
				}
			}
			c := f.begin(t)
			p, e := f.service.Prepare(t.Context(), c.OperationID, signAuthentication(t, f.key, c.SigningPayload))
			if e != nil {
				t.Fatal(e)
			}
			if want == "" {
				if p.Outcome != "READY" {
					t.Fatal(p)
				}
				f.close(t, p)
			} else if p.Outcome != "BLOCKED" || p.Blocker != want || p.ReceiptToken != "" || p.ConfirmationToken != "" {
				t.Fatal(p)
			}
		})
	}
}
