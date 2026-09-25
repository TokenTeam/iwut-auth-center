package mongo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/adapter/associationcrypto"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/adapter/emailloginprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	email "iwut-auth-center/internal/emailbinding/domain"
	d "iwut-auth-center/internal/emaillogin/domain"
	uc "iwut-auth-center/internal/emaillogin/usecase"
	identity "iwut-auth-center/internal/identity/domain"
	regusecase "iwut-auth-center/internal/registration/usecase"
)

type fixedLoginProtocol struct{ *emailloginprotocol.Protocol }

func (fixedLoginProtocol) NewCode() (string, error) { return "00005678", nil }

type emailLoginFixture struct {
	*emailFixture
	login *uc.Login
	lr    *EmailLoginRepository
	lp    fixedLoginProtocol
	owner auth.Established
}

func newEmailLoginFixture(t *testing.T) *emailLoginFixture {
	t.Helper()
	f := newEmailFixture(t)
	key := newSigningKey(t)
	started, e := f.service.Begin(t.Context(), emailBegin(key, "login@example.test"), nil)
	if e != nil {
		t.Fatal(e)
	}
	activated, e := completeEmail(t, f, key, started)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := emailloginprotocol.New("iwut-auth-center:test", bytes.Repeat([]byte{7}, 32), email.NormalizeEmail)
	r, e := NewEmailLoginRepository(f.repo, p.KeyID(), EmailLimits{5, 5, 20, 1000})
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Initialize(t.Context(), time.Now()); e != nil {
		t.Fatal(e)
	}
	limiter, _ := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 100000, CompleteGlobal: 100000, BeginSource: 100000, CompleteLocator: 100000, MaxBuckets: 10000})
	lp := fixedLoginProtocol{p}
	service, e := uc.New(r, lp, f.protocol, f.sender, limiter, "iwut-auth-center:test", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	return &emailLoginFixture{f, service, r, lp, *activated.Registration}
}

// Reset only isolated test mail quotas; account/binding authority is always
// established by real UC011 transactions, never a fixture mailbox directory.
func clearMailCooldown(t *testing.T, f *emailLoginFixture) {
	t.Helper()
	if _, e := f.db.Collection(EmailQuotaCollection).DeleteMany(t.Context(), bson.M{}); e != nil {
		t.Fatal(e)
	}
}
func loginBegin(key *ecdsa.PrivateKey, email string) d.Begin {
	return d.Begin{RequestID: uuid.NewString(), Email: email, ProtocolVersion: auth.ProtocolVersion, PublicKey: elliptic.Marshal(elliptic.P256(), key.X, key.Y), Source: "controlled-peer"}
}
func loginSignature(t *testing.T, key *ecdsa.PrivateKey, c d.Challenge) []byte {
	t.Helper()
	sum := sha256.Sum256(c.SigningPayload)
	s, e := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestEmailLoginExistingAccountReuseQuotaAndSessionConsumers(t *testing.T) {
	f := newEmailLoginFixture(t)
	key := newSigningKey(t)
	b := loginBegin(key, "login@example.test")
	if _, e := f.login.Begin(t.Context(), b); !errors.Is(e, d.ErrRate) {
		t.Fatalf("UC011 quota was bypassed: %v", e)
	}
	clearMailCooldown(t, f)
	c, e := f.login.Begin(t.Context(), b)
	if e != nil {
		t.Fatal(e)
	}
	again, e := f.login.Begin(t.Context(), b)
	if e != nil || again.OperationID != c.OperationID {
		t.Fatal("idempotent begin", e)
	}
	conflict := b
	conflict.Email = "other@example.test"
	if _, e = f.login.Begin(t.Context(), conflict); !errors.Is(e, d.ErrConflict) {
		t.Fatal("request conflict", e)
	}
	a, e := f.login.Complete(t.Context(), c.OperationID, "00005678", loginSignature(t, key, c), "peer")
	if e != nil {
		t.Fatal(e)
	}
	if a.AuthID != f.owner.AuthID {
		t.Fatal("new account created")
	}
	for _, collection := range []string{PrincipalCollection, AssociationCollection, AssociationMemberCollection, EmailBindingCollection} {
		if n := countEmail(t, f.emailFixture, collection); n != 1 {
			t.Fatalf("%s changed: %d", collection, n)
		}
	}
	digest, _ := f.protocol.TokenDigest(a.SessionToken)
	session, e := f.repo.CheckSession(t.Context(), digest, time.Now())
	if e != nil || session.EmailBindingRevision != 1 || session.AuthenticationMethod != d.AuthenticationMethod {
		t.Fatal("session check", e)
	}
	if _, e = f.email.Own(t.Context(), digest, time.Now()); e != nil {
		t.Fatal("UC011 consumer", e)
	}
	identityRepo, _ := NewIdentityRepository(f.repo.AuthenticationRepository)
	if e = identityRepo.WithSession(t.Context(), digest, func(s identity.Snapshot, _ time.Time) error {
		if s.AuthID != a.AuthID {
			t.Fatal("identity changed")
		}
		return nil
	}); e != nil {
		t.Fatal("UC010 consumer", e)
	}
	clearMailCooldown(t, f)
	b.RequestID = uuid.NewString()
	reuse, e := f.login.Begin(t.Context(), b)
	if e != nil {
		t.Fatal(e)
	}
	a2, e := f.login.Complete(t.Context(), reuse.OperationID, "00005678", loginSignature(t, key, reuse), "peer")
	if e != nil || a2.CredentialID != a.CredentialID {
		t.Fatal("credential reuse", e)
	}
	// Real UC011 replacement invalidates pending login but preserves established device Sessions.
	clearMailCooldown(t, f)
	pendingKey := newSigningKey(t)
	pending, e := f.login.Begin(t.Context(), loginBegin(pendingKey, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	ownerDigest, _ := f.protocol.TokenDigest(f.owner.SessionToken)
	revision := int64(1)
	bind, e := f.service.Begin(t.Context(), email.Begin{RequestID: uuid.NewString(), Email: "changed@example.test", Mode: email.Bind, Revision: &revision, Source: "peer"}, ownerDigest)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.Complete(t.Context(), bind.Operation.Proof.OperationID, "00001234", nil, false, ownerDigest); e != nil {
		t.Fatal(e)
	}
	if _, e = f.login.Complete(t.Context(), pending.OperationID, "00005678", loginSignature(t, pendingKey, pending), "peer"); !errors.Is(e, d.ErrFailed) {
		t.Fatal("changed email accepted pending login", e)
	}
	op, e := f.lr.Get(t.Context(), pending.OperationID)
	if e != nil || op.EmailBindingRevision != 1 {
		t.Fatal(e)
	}
	if _, e = f.repo.CheckSession(t.Context(), digest, time.Now()); e != nil {
		t.Fatal("email replacement revoked device session", e)
	}
	if e = f.repo.RevokeOwnCredential(t.Context(), session, a.CredentialID, time.Now()); e != nil {
		t.Fatal("UC009 consumer", e)
	}
	if _, e = f.repo.CheckSession(t.Context(), digest, time.Now()); !errors.Is(e, ap.ErrSessionInvalid) {
		t.Fatal("revoked email device session remained valid", e)
	}
	raw, e := f.db.Collection(EmailLoginAuditCollection).FindOne(t.Context(), bson.M{}).Raw()
	if e != nil || bytes.Contains(raw, []byte("login@example.test")) || bytes.Contains(raw, []byte("00005678")) || bytes.Contains(raw, []byte(a.SessionToken)) {
		t.Fatal("audit privacy", e)
	}
}
func TestEmailLoginFrozenUnknownFailuresAndRotation(t *testing.T) {
	f := newEmailLoginFixture(t)
	key := newSigningKey(t)
	b := loginBegin(key, "unknown@example.test")
	c, e := f.login.Begin(t.Context(), b)
	if e != nil {
		t.Fatal(e)
	}
	clearMailCooldown(t, f)
	registrationKey := newSigningKey(t)
	registered, e := f.service.Begin(t.Context(), emailBegin(registrationKey, b.Email), nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = completeEmail(t, f.emailFixture, registrationKey, registered); e != nil {
		t.Fatal(e)
	}
	sig := loginSignature(t, key, c)
	if _, e = f.login.Complete(t.Context(), c.OperationID, "00005678", sig, "peer"); !errors.Is(e, d.ErrFailed) {
		t.Fatal("placeholder became eligible", e)
	}
	clearMailCooldown(t, f)
	valid, e := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := f.login.Complete(t.Context(), valid.OperationID, "99999999", sig, "peer")
			if !errors.Is(e, d.ErrFailed) {
				t.Errorf("failure: %v", e)
			}
		}()
	}
	wg.Wait()
	op, e := f.lr.Get(t.Context(), valid.OperationID)
	if e != nil || op.Status != auth.Closed || op.FailedAttempts != 5 {
		t.Fatalf("attempt bound: %+v %v", op, e)
	}
	clearMailCooldown(t, f)
	b = loginBegin(newSigningKey(t), "login@example.test")
	pending, e := f.login.Begin(t.Context(), b)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.lr.Initialize(t.Context(), time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = f.login.Begin(t.Context(), b); e != nil {
		t.Fatal("same-key restart", e)
	}
	p, _ := emailloginprotocol.New("iwut-auth-center:test", bytes.Repeat([]byte{8}, 32), email.NormalizeEmail)
	rotated, _ := NewEmailLoginRepository(f.repo, p.KeyID(), EmailLimits{5, 5, 20, 1000})
	if e = rotated.Initialize(t.Context(), time.Now()); e != nil {
		t.Fatal(e)
	}
	op, e = f.lr.Get(t.Context(), pending.OperationID)
	if e != nil || op.Status != auth.Closed {
		t.Fatal("rotation failed", e)
	}
}
func TestEmailLoginRollbackConcurrencyAndLRU(t *testing.T) {
	f := newEmailLoginFixture(t)
	clearMailCooldown(t, f)
	key := newSigningKey(t)
	c, e := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	sig := loginSignature(t, key, c)
	if e = f.db.CreateCollection(t.Context(), EmailLoginAuditCollection); e != nil {
		t.Fatal(e)
	}
	if e = f.db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: EmailLoginAuditCollection}, {Key: "validator", Value: bson.M{"impossible": bson.M{"$exists": true}}}}).Err(); e != nil {
		t.Fatal(e)
	}
	result, e := f.login.Complete(t.Context(), c.OperationID, "00005678", sig, "peer")
	if !errors.Is(e, d.ErrUnavailable) || result.SessionToken != "" || countEmail(t, f.emailFixture, CredentialCollection) != 1 || countEmail(t, f.emailFixture, SessionCollection) != 1 {
		t.Fatal("atomic rollback failed", e)
	}
	if e = f.db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: EmailLoginAuditCollection}, {Key: "validator", Value: bson.M{}}}).Err(); e != nil {
		t.Fatal(e)
	}
	successes := make(chan auth.Established, 20)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, e := f.login.Complete(t.Context(), c.OperationID, "00005678", sig, "peer")
			if e == nil {
				successes <- a
			} else if !errors.Is(e, d.ErrCompleted) {
				t.Errorf("concurrent completion: %v", e)
			}
		}()
	}
	wg.Wait()
	if len(successes) != 1 {
		t.Fatal("operation completed more than once")
	}
	type pending struct {
		c   d.Challenge
		sig []byte
	}
	operations := []pending{}
	for range 12 {
		clearMailCooldown(t, f)
		k := newSigningKey(t)
		c, e := f.login.Begin(t.Context(), loginBegin(k, "login@example.test"))
		if e != nil {
			t.Fatal(e)
		}
		operations = append(operations, pending{c, loginSignature(t, k, c)})
	}
	for _, op := range operations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := f.login.Complete(t.Context(), op.c.OperationID, "00005678", op.sig, "peer"); e != nil {
				t.Errorf("parallel LRU: %v", e)
			}
		}()
	}
	wg.Wait()
	count, e := f.db.Collection(SessionCollection).CountDocuments(t.Context(), bson.M{"authId": f.owner.AuthID, "revokedAt": nil})
	if e != nil || count != 10 {
		t.Fatalf("Session cap %d: %v", count, e)
	}
	if countEmail(t, f.emailFixture, PrincipalCollection) != 1 || countEmail(t, f.emailFixture, CredentialCollection) != 14 {
		t.Fatal("parallel login changed account or duplicated credential")
	}
}
func TestEmailLoginUnknownCommitNeverReturnsToken(t *testing.T) {
	f := newEmailLoginFixture(t)
	clearMailCooldown(t, f)
	key := newSigningKey(t)
	c, e := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	fault, name := sessionRevocationFaultRepository(t, f.db)
	reg, _ := NewRegistrationRepository(fault.database, fault)
	repo, _ := NewEmailLoginRepository(reg, f.lp.KeyID(), EmailLimits{5, 5, 20, 1000})
	limiter, _ := deviceprotocol.NewLimiter(deviceprotocol.DefaultRateLimits())
	service, _ := uc.New(repo, f.lp, f.protocol, f.sender, limiter, "iwut-auth-center:test", time.Hour)
	admin := f.db.Client().Database("admin")
	disable := func() {
		admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}})
	}
	t.Cleanup(disable)
	if e = admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": name, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	a, e := service.Complete(ctx, c.OperationID, "00005678", loginSignature(t, key, c), "peer")
	cancel()
	if !errors.Is(e, d.ErrUnavailable) || a.SessionToken != "" {
		t.Fatal("unknown commit released token", e)
	}
	disable()
	if _, e = service.Complete(t.Context(), c.OperationID, "00005678", loginSignature(t, key, c), "peer"); e != nil && !errors.Is(e, d.ErrCompleted) {
		t.Fatal(e)
	}
}

func TestEmailLoginCrossAccountRevokedAndCompetingRegistration(t *testing.T) {
	f := newEmailLoginFixture(t)
	otherKey := newSigningKey(t)
	registered, e := f.service.Begin(t.Context(), emailBegin(otherKey, "other@example.test"), nil)
	if e != nil {
		t.Fatal(e)
	}
	other, e := completeEmail(t, f.emailFixture, otherKey, registered)
	if e != nil {
		t.Fatal(e)
	}
	clearMailCooldown(t, f)
	cross, e := f.login.Begin(t.Context(), loginBegin(otherKey, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.login.Complete(t.Context(), cross.OperationID, "99999999", loginSignature(t, otherKey, cross), "peer"); !errors.Is(e, d.ErrFailed) {
		t.Fatal("conflict disclosed before proofs", e)
	}
	if _, e = f.login.Complete(t.Context(), cross.OperationID, "00005678", loginSignature(t, otherKey, cross), "peer"); !errors.Is(e, d.ErrCredential) {
		t.Fatal("cross account public key accepted", e)
	}
	digest, _ := f.protocol.TokenDigest(other.Registration.SessionToken)
	caller, e := f.repo.CheckSession(t.Context(), digest, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.repo.RevokeOwnCredential(t.Context(), caller, other.Registration.CredentialID, time.Now()); e != nil {
		t.Fatal(e)
	}
	clearMailCooldown(t, f)
	revoked, e := f.login.Begin(t.Context(), loginBegin(otherKey, "other@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.login.Complete(t.Context(), revoked.OperationID, "00005678", loginSignature(t, otherKey, revoked), "peer"); !errors.Is(e, d.ErrCredential) {
		t.Fatal("revoked public key revived", e)
	}
	clearMailCooldown(t, f)
	key := newSigningKey(t)
	c, e := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	reg := beginRegistration(t, f.registrationFixture, key, bytes.Repeat([]byte{4}, 32))
	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, e := f.login.Complete(t.Context(), c.OperationID, "00005678", loginSignature(t, key, c), "peer")
		results <- e
	}()
	go func() {
		defer wg.Done()
		_, e := f.uc.Complete(t.Context(), reg.OperationID, signChallenge(t, key, reg))
		results <- e
	}()
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		} else if !errors.Is(e, d.ErrCredential) && !errors.Is(e, ap.ErrCredentialRegistered) {
			t.Fatal("unexpected competing proof error", e)
		}
	}
	if successes != 1 {
		t.Fatal("one public key gained multiple owners")
	}
	fingerprint, _ := f.protocol.Fingerprint(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
	n, e := f.db.Collection(CredentialCollection).CountDocuments(t.Context(), bson.M{"fingerprint": fingerprint})
	if e != nil || n != 1 {
		t.Fatal("global key uniqueness", e)
	}
}
func TestEmailLoginAssociationRotationDoesNotCloseOperation(t *testing.T) {
	f := newEmailLoginFixture(t)
	clearMailCooldown(t, f)
	key := newSigningKey(t)
	c, e := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	current := associationcrypto.Key{Version: "v2", Encrypt: bytes.Repeat([]byte{5}, 32), Lookup: bytes.Repeat([]byte{6}, 32)}
	previous := associationcrypto.Key{Version: "v1", Encrypt: bytes.Repeat([]byte{1}, 32), Lookup: bytes.Repeat([]byte{2}, 32)}
	cipher, e := associationcrypto.New(current, &previous)
	if e != nil {
		t.Fatal(e)
	}
	migration, _ := NewAssociationMigrationRepository(f.db)
	if e = regusecase.MigrateAssociations(t.Context(), migration, cipher, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = f.login.Complete(t.Context(), c.OperationID, "00005678", loginSignature(t, key, c), "peer"); e != nil {
		t.Fatal("unrelated association invalidated login", e)
	}
}

func TestEmailLoginAndEmailReplacementCommitOrder(t *testing.T) {
	f := newEmailLoginFixture(t)
	clearMailCooldown(t, f)
	key := newSigningKey(t)
	challenge, e := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	digest, _ := f.protocol.TokenDigest(f.owner.SessionToken)
	revision := int64(1)
	binding, e := f.service.Begin(t.Context(), email.Begin{RequestID: uuid.NewString(), Email: "replacement@example.test", Mode: email.Bind, Revision: &revision, Source: "peer"}, digest)
	if e != nil {
		t.Fatal(e)
	}
	var result auth.Established
	var loginErr, bindErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		result, loginErr = f.login.Complete(t.Context(), challenge.OperationID, "00005678", loginSignature(t, key, challenge), "peer")
	}()
	go func() {
		defer wg.Done()
		_, bindErr = f.service.Complete(t.Context(), binding.Operation.Proof.OperationID, "00001234", nil, false, digest)
	}()
	wg.Wait()
	if bindErr != nil {
		t.Fatal(bindErr)
	}
	if loginErr != nil && !errors.Is(loginErr, d.ErrFailed) {
		t.Fatal(loginErr)
	}
	if loginErr == nil {
		sessionDigest, _ := f.protocol.TokenDigest(result.SessionToken)
		if _, e = f.repo.CheckSession(t.Context(), sessionDigest, time.Now()); e != nil {
			t.Fatal("earlier login revoked by later replacement", e)
		}
	}
	// Even restoring the original address cannot restore revision 1's challenge.
	clearMailCooldown(t, f)
	revision = 2
	back, e := f.service.Begin(t.Context(), email.Begin{RequestID: uuid.NewString(), Email: "login@example.test", Mode: email.Bind, Revision: &revision, Source: "peer"}, digest)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.Complete(t.Context(), back.Operation.Proof.OperationID, "00001234", nil, false, digest); e != nil {
		t.Fatal(e)
	}
	_, e = f.login.Complete(t.Context(), challenge.OperationID, "00005678", loginSignature(t, key, challenge), "peer")
	if loginErr == nil {
		if !errors.Is(e, d.ErrCompleted) {
			t.Fatal(e)
		}
	} else if !errors.Is(e, d.ErrFailed) {
		t.Fatal("restored email revived old revision", e)
	}
}
func TestEmailLoginDisabledEligibilityRemainsFrozen(t *testing.T) {
	f := newEmailLoginFixture(t)
	clearMailCooldown(t, f)
	if _, e := f.db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.owner.AuthID}, bson.M{"$set": bson.M{"accountStatus": "DISABLED"}}); e != nil {
		t.Fatal(e)
	}
	key := newSigningKey(t)
	challenge, e := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if e != nil {
		t.Fatal("disabled mailbox begin leaked account status", e)
	}
	if _, e = f.db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.owner.AuthID}, bson.M{"$set": bson.M{"accountStatus": "ACTIVE"}}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.login.Complete(t.Context(), challenge.OperationID, "00005678", loginSignature(t, key, challenge), "peer"); !errors.Is(e, d.ErrFailed) {
		t.Fatal("reenabled account revived placeholder", e)
	}
}
func TestEmailLoginUC008RejectsUnknownAndCorruptMethods(t *testing.T) {
	f := newEmailLoginFixture(t)
	digest, _ := f.protocol.TokenDigest(f.owner.SessionToken)
	for _, change := range []bson.M{{"authenticationMethod": "FUTURE_UNKNOWN"}, {"authenticationMethod": d.AuthenticationMethod, "emailBindingRevision": int64(0)}} {
		if _, e := f.db.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": f.owner.SessionID}, bson.M{"$set": change}); e != nil {
			t.Fatal(e)
		}
		if e := f.repo.RevokeCurrentSession(t.Context(), digest, time.Now()); !errors.Is(e, ap.ErrUnavailable) {
			t.Fatal("UC008 trusted unknown/corrupt method", e)
		}
	}
}
