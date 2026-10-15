package mongo

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	cd "iwut-auth-center/internal/accountclosure/domain"
	cp "iwut-auth-center/internal/accountclosure/port"
	cu "iwut-auth-center/internal/accountclosure/usecase"
	"iwut-auth-center/internal/adapter/closureprotocol"
	"iwut-auth-center/internal/adapter/terminationledger"
	admin "iwut-auth-center/internal/administrator/domain"
	ap "iwut-auth-center/internal/authentication/port"
	developer "iwut-auth-center/internal/developer/domain"
	owner "iwut-auth-center/internal/ownerexit/domain"
	pwdport "iwut-auth-center/internal/password/port"
	pwdusecase "iwut-auth-center/internal/password/usecase"
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
	prepare func()
	calls   int
}

func (a *closureAppStub) Prepare(_ context.Context, o owner.Operation) (owner.Preparation, error) {
	a.calls++
	if a.prepare != nil {
		a.prepare()
	}
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
	repo     *AccountClosureRepository
	service  *cu.Service
	app      *closureAppStub
	ledger   *closureLedgerFault
	clock    time.Time
	verifier pwdport.PasswordVerifier
}

func newClosureFixture(t *testing.T) *closureFixture {
	t.Helper()
	a := newAuthenticationFixture(t)
	return buildClosureFixture(t, a)
}
func buildClosureFixture(t *testing.T, a authenticationFixture) *closureFixture {
	t.Helper()
	db := a.r.database
	passwords := attachPassword(t, a)
	verifier, err := pwdusecase.NewReauth(passwords.repository, passwords.engine, passwords.quota)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []error{EnsureAccountClosureSchema(t.Context(), db), EnsureOwnerExitSchema(t.Context(), db), EnsureCampusSchema(t.Context(), db)} {
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
	f := &closureFixture{authenticationFixture: a, repo: repo, app: &closureAppStub{receipt: id.String()}, ledger: &closureLedgerFault{TerminationLedger: ledger}, clock: time.Now().UTC().Truncate(time.Millisecond), verifier: verifier}
	f.service, e = cu.New(repo, p, f.app, NewOwnerExitRepository(a.r), f.ledger, "iwut-auth-center:test", verifier)
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
	p, e := f.service.Prepare(t.Context(), c.OperationID, signAuthentication(t, f.key, c.SigningPayload), initialPassword, "127.0.0.1")
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
		if _, e = f.service.Prepare(t.Context(), a.OperationID, signAuthentication(t, f.key, a.SigningPayload), initialPassword, "127.0.0.1"); !errors.Is(e, cd.ErrProof) {
			t.Fatal(e)
		}
	}
	o, e := f.repo.Read(t.Context(), a.OperationID)
	if e != nil || o.FailedAttempts != 5 {
		t.Fatalf("attempts=%d err=%v", o.FailedAttempts, e)
	}
	c := f.begin(t)
	ordinary := f.authenticationFixture.begin(t)
	if _, e = f.service.Prepare(t.Context(), c.OperationID, signAuthentication(t, f.key, ordinary.SigningPayload), initialPassword, "127.0.0.1"); !errors.Is(e, cd.ErrProof) {
		t.Fatalf("login signature accepted=%v", e)
	}
	f.clock = f.clock.Add(25 * time.Hour)
	fresh, e := f.service.Begin(t.Context(), in)
	if e != nil || fresh.OperationID == a.OperationID {
		t.Fatalf("24-hour dedupe did not expire=%v %v", fresh, e)
	}

}
func TestAccountClosurePreviewChangesInvalidate(t *testing.T) {
	for _, change := range []string{"email", "key", "other_key", "permission", "developer", "account", "password", "credential_cutoff"} {
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
				_, e = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"developerRevision": int64(1)}, "$set": bson.M{"developerStatus": "PENDING"}})
			case "password":
				_, e = db.Collection(PasswordCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"passwordRevision": int64(1)}})
			case "credential_cutoff":
				_, e = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"minimumCredentialRevision": int64(2), "accountRevision": int64(2)}})
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
	for _, id := range []string{auth, "other"} {
		closureInsert(t, f, CampusCertificationCollection, bson.M{"authId": id, "institution": "WHUT", "certifiedAt": now})
		closureInsert(t, f, CampusVerificationCollection, bson.M{"operationId": "campus-" + id, "authId": id, "email": "campus@whut.edu.cn", "requestMac": []byte("secret")})
		for _, col := range []string{PasswordCollection, PasswordChangeCollection, PasswordNotificationCollection} {
			if col == PasswordCollection {
				if id == auth {
					continue // The fixture already contains the real current password.
				}
				var original passwordDocument
				if e := f.r.database.Collection(col).FindOne(t.Context(), bson.M{"authId": auth}).Decode(&original); e != nil {
					t.Fatal(e)
				}
				original.AuthID = id
				closureInsert(t, f, col, original)
				continue
			}
			closureInsert(t, f, col, bson.M{"authId": id, "operationId": "password-" + id, "eventId": "password-" + id, "privateFixture": "erase"})
		}
	}
	for _, kind := range []string{"interactions", "codes", "access", "grants", "subjects", "families"} {
		closureInsert(t, f, "auth_oauth_"+kind, bson.M{"_id": kind + "-id", "data": bson.M{"authid": auth, "private": "erase"}})
		closureInsert(t, f, "auth_oauth_"+kind, bson.M{"_id": "other-" + kind, "data": bson.M{"authid": "other"}})
	}
	closureInsert(t, f, "auth_oauth_refresh", bson.M{"_id": "refresh", "data": bson.M{"familyid": "families-id"}})
	ss := f.authenticationFixture.login(t)
	closureInsert(t, f, "auth_oauth_interactions", bson.M{"_id": "unbound-initial-session", "data": bson.M{"authid": "", "initialsessionid": ss.SessionID, "csrfhash": "secret"}})
	p := f.ready(t)
	f.close(t, p)
	f.acknowledge(t, p.OperationID)
	f.drain(t)
	for _, col := range []string{CredentialCollection, SessionCollection, AuthenticationOperationCollection, EmailOperationCollection, EmailBindingCollection, DeveloperActivationCollection} {
		if n := closureCount(t, f, col, bson.M{}); n != 0 {
			t.Fatalf("%s remains %d", col, n)
		}
	}
	for _, col := range []string{PasswordCollection, PasswordChangeCollection, PasswordNotificationCollection} {
		if closureCount(t, f, col, bson.M{"authId": auth}) != 0 || closureCount(t, f, col, bson.M{"authId": "other"}) != 1 {
			t.Fatalf("%s password cleanup isolation failed", col)
		}
	}
	for _, kind := range []string{"interactions", "codes", "access", "grants", "subjects", "families"} {
		if n := closureCount(t, f, "auth_oauth_"+kind, bson.M{}); n != 1 {
			t.Fatalf("%s other ownership count=%d", kind, n)
		}
	}
	if closureCount(t, f, "auth_oauth_refresh", bson.M{}) != 0 || closureCount(t, f, CampusCertificationCollection, bson.M{"authId": "other"}) != 1 || closureCount(t, f, CampusVerificationCollection, bson.M{"authId": "other"}) != 1 || closureCount(t, f, CampusCertificationCollection, bson.M{"authId": auth}) != 0 || closureCount(t, f, CampusVerificationCollection, bson.M{"authId": auth}) != 0 {
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
	if p.Preview.DeveloperHandle != "reserved" {
		t.Fatal("preview omitted authoritative handle")
	}
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
func TestAccountClosureDoesNotTouchOtherCampusVerification(t *testing.T) {
	f := newClosureFixture(t)
	closureInsert(t, f, CampusCertificationCollection, bson.M{"authId": f.c.AuthID, "institution": "WHUT", "certifiedAt": f.clock})
	closureInsert(t, f, CampusVerificationCollection, bson.M{"operationId": "own-campus", "authId": f.c.AuthID, "email": "shared@whut.edu.cn", "requestMac": []byte("personal")})
	closureInsert(t, f, CampusVerificationCollection, bson.M{"operationId": "other-campus", "authId": "other", "email": "shared@whut.edu.cn", "requestMac": []byte("other")})
	closureInsert(t, f, AuthenticationOperationCollection, bson.M{"operationId": "own-campus", "authId": f.c.AuthID, "purpose": "CERTIFY_CAMPUS_WHUT", "status": "PENDING", "expiresAt": f.clock.Add(time.Minute)})
	p := f.ready(t)
	f.close(t, p)
	f.acknowledge(t, p.OperationID)
	f.drain(t)
	if closureCount(t, f, CampusCertificationCollection, bson.M{"authId": f.c.AuthID}) != 0 || closureCount(t, f, CampusVerificationCollection, bson.M{"authId": f.c.AuthID}) != 0 || closureCount(t, f, CampusVerificationCollection, bson.M{"authId": "other"}) != 1 {
		t.Fatal("campus cleanup used shared email instead of immutable authId")
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
	closureInsert(t, f, CampusAuditCollection, bson.M{"authId": f.c.AuthID, "institution": "WHUT", "at": f.clock.Add(-time.Hour), "result": "CERTIFIED"})
	closureInsert(t, f, CampusAuditCollection, bson.M{"authId": "active", "institution": "WHUT", "at": f.clock.Add(-time.Hour), "result": "CERTIFIED"})
	if e := f.repo.Retain(t.Context(), future, 2); e != nil {
		t.Fatal(e)
	}
	if closureCount(t, f, PermissionAuditCollection, bson.M{"eventId": "closed-event"}) != 0 || closureCount(t, f, PermissionAuditCollection, bson.M{"subjectAuthId": "active"}) != 5 {
		t.Fatal("active audits starved closed retention")
	}
	if closureCount(t, f, CampusAuditCollection, bson.M{"authId": f.c.AuthID}) != 0 || closureCount(t, f, CampusAuditCollection, bson.M{"authId": "active"}) != 1 {
		t.Fatal("campus audit retention lost ownership boundary")
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
			p, e := f.service.Prepare(t.Context(), c.OperationID, signAuthentication(t, f.key, c.SigningPayload), initialPassword, "127.0.0.1")
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
func TestAccountClosureRetiresBootstrapAuditAtomically(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprint(corrupt), func(t *testing.T) {
			admins, db, subject := administratorFixture(t)
			a := admins.authentication
			repo, _ := NewAccountClosureRepository(a)
			now := time.Now().UTC().Truncate(time.Millisecond)
			old := now.Add(-181 * 24 * time.Hour)
			_, e := db.Collection(AuthenticationRuntimeCollection).UpdateOne(t.Context(), bson.M{"_id": bootstrapMarker}, bson.M{"$set": bson.M{"occurredAt": old}})
			if e != nil {
				t.Fatal(e)
			}
			_, e = db.Collection(PlatformAdminAuditCollection).UpdateMany(t.Context(), bson.M{"actorType": "BOOTSTRAP_COMMAND"}, bson.M{"$set": bson.M{"occurredAt": old}})
			if e != nil {
				t.Fatal(e)
			}
			tomb := bson.M{"authId": subject, "principalType": "USER", "accountStatus": "CLOSED", "accountRevision": int64(2), "terminatedAt": now.Add(-time.Hour), "closureOperationId": uuid.NewString()}
			if corrupt {
				tomb["profile"] = "must-not-survive"
			}
			_, e = db.Collection(PrincipalCollection).ReplaceOne(t.Context(), bson.M{"authId": subject}, tomb)
			if e != nil {
				t.Fatal(e)
			}
			e = repo.Retain(t.Context(), now, 500)
			if corrupt {
				if !errors.Is(e, cd.ErrUnavailable) {
					t.Fatalf("corrupt retirement=%v", e)
				}
				n, _ := db.Collection(PlatformAdminAuditCollection).CountDocuments(t.Context(), bson.M{})
				if n != 1 {
					t.Fatal("retirement deleted audit after validation failure")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			n, _ := db.Collection(PlatformAdminAuditCollection).CountDocuments(t.Context(), bson.M{})
			if n != 0 {
				t.Fatal("expired bootstrap audit retained")
			}
			if e = a.WithAuthTransaction(t.Context(), func(tx context.Context) error { _, e := a.administratorMarkerTx(tx); return e }); e != nil {
				t.Fatalf("retired marker rejected=%v", e)
			}
		})
	}
}
func TestAccountClosureRecoveryPendingReceiptCannotCancel(t *testing.T) {
	f := newClosureFixture(t)
	p := f.ready(t)
	f.close(t, p)
	records, e := f.ledger.Records(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.r.database.Collection(OwnerExitCollection).UpdateOne(t.Context(), bson.M{"operationId": p.OperationID}, bson.M{"$set": bson.M{"decision": owner.Pending, "receiptId": "", "notificationPending": false, "appAcknowledged": false}, "$unset": bson.M{"decidedAt": ""}})
	if e != nil {
		t.Fatal(e)
	}
	if e = f.repo.Replay(t.Context(), records[0]); e != nil {
		t.Fatal(e)
	}
	owners := NewOwnerExitRepository(f.r)
	if _, e = owners.Get(t.Context(), f.c.AuthID, p.OperationID); !errors.Is(e, owner.ErrUnavailable) {
		t.Fatalf("recovering decision exposed=%v", e)
	}
	due, e := owners.Due(t.Context(), f.clock.Add(10*time.Minute), 100)
	if e != nil || len(due) != 0 {
		t.Fatalf("recovery mistaken for cancellable pending=%v err=%v", due, e)
	}
	if e = f.service.Tick(t.Context()); e != nil {
		t.Fatal(e)
	}
	o, e := owners.Get(t.Context(), f.c.AuthID, p.OperationID)
	if e != nil || o.Decision != owner.Committed || o.ReceiptID != f.app.receipt {
		t.Fatalf("recovered=%v err=%v", o, e)
	}
}
func TestAccountClosureBatch500ResumesAfterRestart(t *testing.T) {
	f := newClosureFixture(t)
	p := f.ready(t)
	f.close(t, p)
	var rows []any
	for i := 0; i < 501; i++ {
		rows = append(rows, bson.M{"authId": f.c.AuthID, "sessionId": uuid.NewString(), "tokenDigest": []byte(fmt.Sprintf("digest-%d", i))})
	}
	if _, e := f.r.database.Collection(SessionCollection).InsertMany(t.Context(), rows); e != nil {
		t.Fatal(e)
	}
	if _, e := f.r.database.Collection(AccountClosureTaskCollection).UpdateOne(t.Context(), bson.M{"operationId": p.OperationID}, bson.M{"$set": bson.M{"step": 10}}); e != nil {
		t.Fatal(e)
	}
	if _, e := f.repo.Cleanup(t.Context(), p.OperationID, f.clock, 500); e != nil {
		t.Fatal(e)
	}
	if n := closureCount(t, f, SessionCollection, bson.M{"authId": f.c.AuthID}); n != 1 {
		t.Fatalf("batch removed wrong count, remains=%d", n)
	}
	restarted, e := NewAccountClosureRepository(f.r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restarted.Cleanup(t.Context(), p.OperationID, f.clock, 500); e != nil {
		t.Fatal(e)
	}
	if n := closureCount(t, f, SessionCollection, bson.M{"authId": f.c.AuthID}); n != 0 {
		t.Fatalf("restart did not resume=%d", n)
	}
}
func TestAccountClosureReceiptExpiryIndependentOfRecovery(t *testing.T) {
	f := newClosureFixture(t)
	p := f.ready(t)
	f.close(t, p)
	_, e := f.r.database.Collection(OwnerExitCollection).UpdateOne(t.Context(), bson.M{"operationId": p.OperationID}, bson.M{"$set": bson.M{"recoveryReceiptRequired": true}})
	if e != nil {
		t.Fatal(e)
	}
	f.clock = f.clock.Add(31 * 24 * time.Hour)
	if e = f.repo.Retain(t.Context(), f.clock, 500); e != nil {
		t.Fatal(e)
	}
	var raw bson.Raw
	if e = f.r.database.Collection(AccountClosureCollection).FindOne(t.Context(), bson.M{"operationId": p.OperationID}).Decode(&raw); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"confirmationDigest", "receiptDigest", "publicKey"} {
		if raw.Lookup(field).Type != 0 {
			t.Fatalf("expired %s retained while App unavailable", field)
		}
	}
	if closureCount(t, f, AccountClosureTaskCollection, bson.M{"operationId": p.OperationID}) != 1 {
		t.Fatal("unfinished task lost")
	}
	if _, e = f.service.Get(t.Context(), p.OperationID, p.ReceiptToken); !errors.Is(e, cd.ErrToken) {
		t.Fatalf("expired receipt usable=%v", e)
	}
}

type closurePasswordVerifierFunc func(context.Context, pwdport.ReauthRequest) (int64, error)

func (f closurePasswordVerifierFunc) VerifyPassword(ctx context.Context, request pwdport.ReauthRequest) (int64, error) {
	return f(ctx, request)
}

func (f *closureFixture) setVerifier(t *testing.T, verifier pwdport.PasswordVerifier) {
	t.Helper()
	protocol, err := closureprotocol.New("iwut-auth-center:test")
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = cu.New(f.repo, protocol, f.app, NewOwnerExitRepository(f.r), f.ledger, "iwut-auth-center:test", verifier)
	if err != nil {
		t.Fatal(err)
	}
	f.service.SetClock(func() time.Time { return f.clock })
}

func TestAccountClosurePasswordAndSignatureShareFiveFailures(t *testing.T) {
	f := newClosureFixture(t)
	c := f.begin(t)
	signature := signAuthentication(t, f.key, c.SigningPayload)
	if _, err := f.service.Prepare(t.Context(), c.OperationID, signature, "", "127.0.0.1"); !errors.Is(err, cd.ErrInvalid) {
		t.Fatal("omitted password was accepted", err)
	}
	for i := 0; i < 5; i++ {
		proof := signature
		password := "wrong but well formed password"
		if i < 2 {
			ordinary := f.authenticationFixture.begin(t)
			proof = signAuthentication(t, f.key, ordinary.SigningPayload)
			password = initialPassword
		}
		result, err := f.service.Prepare(t.Context(), c.OperationID, proof, password, "127.0.0.1")
		if !errors.Is(err, cd.ErrProof) || result.Preview != nil || result.Blocker != "" || result.ConfirmationToken != "" {
			t.Fatal("bad combined proof leaked a result", result, err)
		}
	}
	if _, err := f.service.Prepare(t.Context(), c.OperationID, signature, initialPassword, "127.0.0.1"); !errors.Is(err, cd.ErrProof) {
		t.Fatal("exhausted proof revived", err)
	}
	op, err := f.repo.Read(t.Context(), c.OperationID)
	if err != nil || op.FailedAttempts != 5 || op.PasswordRevision != 0 || f.app.calls != 0 || closureCount(t, f, OwnerExitCollection, bson.M{}) != 0 {
		t.Fatal("failure bound or disclosure fence failed", op, err)
	}
}

func TestAccountClosurePasswordGateDoesNotRevealBlockers(t *testing.T) {
	f := newClosureFixture(t)
	if _, err := f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"permissions": admin.Permissions()}}); err != nil {
		t.Fatal(err)
	}
	c := f.begin(t)
	signature := signAuthentication(t, f.key, c.SigningPayload)
	result, err := f.service.Prepare(t.Context(), c.OperationID, signature, "wrong password", "127.0.0.1")
	if !errors.Is(err, cd.ErrProof) || result.Blocker != "" || f.app.calls != 0 {
		t.Fatal("blocker disclosed before password verification", result, err)
	}
	result, err = f.service.Prepare(t.Context(), c.OperationID, signature, initialPassword, "127.0.0.1")
	if err != nil || result.Outcome != "BLOCKED" || result.Blocker != cd.AdminBlocker || result.Preview != nil || f.app.calls != 0 {
		t.Fatal("password plus proof did not reveal the authorized blocker", result, err)
	}
}

func TestAccountClosureRechecksPasswordAfterHashAndAppPrepare(t *testing.T) {
	for _, stage := range []string{"after_password", "after_app"} {
		t.Run(stage, func(t *testing.T) {
			f := newClosureFixture(t)
			change := func() {
				if _, err := f.r.database.Collection(PasswordCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"passwordRevision": int64(1)}}); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "after_password" {
				f.setVerifier(t, closurePasswordVerifierFunc(func(ctx context.Context, request pwdport.ReauthRequest) (int64, error) {
					revision, err := f.verifier.VerifyPassword(ctx, request)
					if err == nil {
						change()
					}
					return revision, err
				}))
			} else {
				f.app.prepare = change
			}
			c := f.begin(t)
			result, err := f.service.Prepare(t.Context(), c.OperationID, signAuthentication(t, f.key, c.SigningPayload), initialPassword, "127.0.0.1")
			want := cd.ErrProof
			if stage == "after_app" {
				want = cd.ErrConflict
			}
			if !errors.Is(err, want) || result.Preview != nil || result.ConfirmationToken != "" || result.ReceiptToken != "" {
				t.Fatal("stale password attestation authorized closure", result, err)
			}
			o, err := f.repo.Read(t.Context(), c.OperationID)
			if err != nil || o.State != cd.Cancelled {
				t.Fatal("stale preparation was not cancelled", o, err)
			}
		})
	}
}

func TestAccountClosureRecoveryOnlyRuntimeCannotPrepare(t *testing.T) {
	f := newClosureFixture(t)
	f.setVerifier(t, nil)
	c := f.begin(t)
	if _, err := f.service.Prepare(t.Context(), c.OperationID, signAuthentication(t, f.key, c.SigningPayload), initialPassword, "127.0.0.1"); !errors.Is(err, cd.ErrUnavailable) {
		t.Fatal("nil verifier accepted signature-only proof", err)
	}
	if err := f.service.Reconcile(t.Context()); err != nil {
		t.Fatal("password gate broke independent recovery", err)
	}
}

func TestAccountClosureStrictPasswordRevisionAndDependencyFailure(t *testing.T) {
	for _, bad := range []any{nil, int32(1), float64(1), int64(-1)} {
		f := newClosureFixture(t)
		c := f.begin(t)
		if _, err := f.r.database.Collection(AccountClosureCollection).UpdateOne(t.Context(), bson.M{"operationId": c.OperationID}, bson.M{"$set": bson.M{"passwordRevision": bad}}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.Read(t.Context(), c.OperationID); !errors.Is(err, cd.ErrUnavailable) {
			t.Fatal("malformed password revision defaulted", bad, err)
		}
	}
	f := newClosureFixture(t)
	c := f.begin(t)
	if _, err := f.r.database.Collection(PasswordCollection).DeleteOne(t.Context(), bson.M{"authId": f.c.AuthID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Prepare(t.Context(), c.OperationID, signAuthentication(t, f.key, c.SigningPayload), initialPassword, "127.0.0.1"); !errors.Is(err, cd.ErrUnavailable) {
		t.Fatal("missing password synthesized or counted as wrong", err)
	}
	o, err := f.repo.Read(t.Context(), c.OperationID)
	if err != nil || o.FailedAttempts != 0 || f.app.calls != 0 {
		t.Fatal("dependency failure consumed authentication attempts", o, err)
	}
}
