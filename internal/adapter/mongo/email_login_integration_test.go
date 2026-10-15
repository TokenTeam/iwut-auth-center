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
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/adapter/emailaccountprotocol"
	"iwut-auth-center/internal/adapter/emailloginprotocol"
	"iwut-auth-center/internal/adapter/passwordcrypto"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	accountdomain "iwut-auth-center/internal/emailaccount/domain"
	accountusecase "iwut-auth-center/internal/emailaccount/usecase"
	email "iwut-auth-center/internal/emailbinding/domain"
	d "iwut-auth-center/internal/emaillogin/domain"
	uc "iwut-auth-center/internal/emaillogin/usecase"
	identity "iwut-auth-center/internal/identity/domain"
	pwd "iwut-auth-center/internal/password/domain"
	regport "iwut-auth-center/internal/registration/port"
)

type fixedLoginProtocol struct{ *emailloginprotocol.Protocol }

func (fixedLoginProtocol) NewCode() (string, error) { return "00005678", nil }

type fixedAccountProtocol struct{ *emailaccountprotocol.Protocol }

func (fixedAccountProtocol) NewCode() (string, error) { return "00001234", nil }

type emailLoginFixture struct {
	accounts *accountusecase.Service
	*emailFixture
	login *uc.Login
	lr    *EmailLoginRepository
	lp    fixedLoginProtocol
	owner auth.Established
}

func newEmailLoginFixture(t *testing.T) *emailLoginFixture {
	t.Helper()
	f := newEmailFixture(t)
	// This isolated historical fixture starts empty. Retire only its known
	// old indexes before creating all authority through real v3 transactions.
	for _, name := range []string{"authId_1", "email_1"} {
		if err := f.db.Collection(EmailBindingCollection).Indexes().DropOne(t.Context(), name); err != nil {
			t.Fatal(err)
		}
	}
	for _, err := range []error{EnsureEmailAccountSchema(t.Context(), f.db), EnsurePasswordSchema(t.Context(), f.db), EnsurePasswordQuotaSchema(t.Context(), f.db)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	protocol, _ := emailaccountprotocol.New(bytes32(3), bytes32(42), "iwut-auth-center:test")
	pwdProtocol, _ := passwordcrypto.NewProtocol(bytes32(42), "iwut-auth-center:test")
	passwords, _ := NewPasswordRepository(f.repo.AuthenticationRepository, pwdProtocol.KeyID())
	quota, _ := NewPasswordQuota(f.repo.AuthenticationRepository)
	repo, e := NewEmailAccountRepository(f.repo, passwords, protocol.KeyID(), EmailLimits{5, 5, 20, 1000})
	if e != nil {
		t.Fatal(e)
	}
	accounts, e := accountusecase.New(repo, fixedAccountProtocol{protocol}, f.protocol, passwordEngine(t, pwd.DefaultParameters()), quota, f.sender, "iwut-auth-center:test", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	temp := &emailLoginFixture{emailFixture: f, accounts: accounts}
	key := newSigningKey(t)
	started, e := temp.beginRegistration(t, key, "login@example.test")
	if e != nil {
		t.Fatal(e)
	}
	activated, e := temp.completeRegistration(t, key, started)
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
	return &emailLoginFixture{emailFixture: f, accounts: accounts, login: service, lr: r, lp: lp, owner: *activated.Registration}
}

func (f *emailLoginFixture) beginRegistration(t *testing.T, key *ecdsa.PrivateKey, email string) (accountusecase.Started, error) {
	return f.accounts.Begin(t.Context(), "", accountdomain.Begin{RequestID: uuid.NewString(), Email: email, DeviceVersion: auth.ProtocolVersion, PublicKey: elliptic.Marshal(elliptic.P256(), key.X, key.Y), Source: "127.0.0.1"}, true)
}
func (f *emailLoginFixture) completeRegistration(t *testing.T, key *ecdsa.PrivateKey, o accountusecase.Started) (accountusecase.Completed, error) {
	return f.accounts.Complete(t.Context(), "", o.Operation.OperationID, "00001234", initialPassword, signAuthentication(t, key, o.SigningPayload), true, "127.0.0.1")
}
func (f *emailLoginFixture) addForSwitch(t *testing.T, address string) accountdomain.Directory {
	t.Helper()
	clearMailCooldown(t, f) // Isolate role-CAS tests from the separately tested shared send budget.
	directory, err := f.accounts.Own(t.Context(), f.owner.SessionToken, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	o, err := f.accounts.Begin(t.Context(), f.owner.SessionToken, accountdomain.Begin{RequestID: uuid.NewString(), Email: address, ExpectedDirectoryRevision: directory.Revision, Source: "127.0.0.1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.accounts.Complete(t.Context(), f.owner.SessionToken, o.Operation.OperationID, "00001234", "", nil, false, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return out.Directory
}
func (f *emailLoginFixture) switchEmail(t *testing.T, directory accountdomain.Directory, address string) error {
	target := ""
	for _, b := range directory.Bindings {
		if b.Email == address {
			target = b.BindingID
		}
	}
	_, _, err := f.accounts.Mutate(t.Context(), f.owner.SessionToken, accountdomain.Mutation{RequestID: uuid.NewString(), BindingID: target, Password: initialPassword, ExpectedDirectoryRevision: directory.Revision, ExpectedLoginRoleRevision: directory.LoginRoleRevision, Source: "127.0.0.1"}, true)
	return err
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
	return d.Begin{RequestID: uuid.NewString(), Email: email, ProtocolVersion: auth.ProtocolVersion, PublicKey: elliptic.Marshal(elliptic.P256(), key.X, key.Y), Source: "127.0.0.1"}
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
	a, e := f.login.Complete(t.Context(), c.OperationID, "00005678", loginSignature(t, key, c), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if a.AuthID != f.owner.AuthID {
		t.Fatal("new account created")
	}
	for _, collection := range []string{PrincipalCollection, EmailBindingCollection} {
		if n := countEmail(t, f.emailFixture, collection); n != 1 {
			t.Fatalf("%s changed: %d", collection, n)
		}
	}
	for _, collection := range []string{AssociationCollection, AssociationMemberCollection} {
		if n := countEmail(t, f.emailFixture, collection); n != 0 {
			t.Fatal("retired association written", n)
		}
	}
	digest, _ := f.protocol.TokenDigest(a.SessionToken)
	session, e := f.repo.CheckSession(t.Context(), digest, time.Now())
	if e != nil || session.EmailBindingRevision != 1 || session.AuthenticationMethod != d.AuthenticationMethod {
		t.Fatal("session check", e)
	}
	if _, e = ReadEmailDirectoryTx(t.Context(), f.db, a.AuthID); e != nil {
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
	a2, e := f.login.Complete(t.Context(), reuse.OperationID, "00005678", loginSignature(t, key, reuse), "127.0.0.1")
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
	directory := f.addForSwitch(t, "changed@example.test")
	if e = f.switchEmail(t, directory, "changed@example.test"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.login.Complete(t.Context(), pending.OperationID, "00005678", loginSignature(t, pendingKey, pending), "127.0.0.1"); !errors.Is(e, d.ErrFailed) {
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

func TestEmailAccountAndLoginShareOwnerMailCooldownAcrossAddresses(t *testing.T) {
	f := newEmailLoginFixture(t)
	// ADD mails a different address, but recovery on the login address must still
	// consume the same owner budget (not just the per-address budget).
	f.addForSwitch(t, "second@example.test")
	if _, err := f.login.Begin(t.Context(), loginBegin(newSigningKey(t), "login@example.test")); !errors.Is(err, d.ErrRate) {
		t.Fatalf("ADD to LOGIN bypassed owner cooldown: %v", err)
	}
	clearMailCooldown(t, f)
	if _, err := f.login.Begin(t.Context(), loginBegin(newSigningKey(t), "login@example.test")); err != nil {
		t.Fatal(err)
	}
	directory, err := f.accounts.Own(t.Context(), f.owner.SessionToken, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.accounts.Begin(t.Context(), f.owner.SessionToken, accountdomain.Begin{RequestID: uuid.NewString(), Email: "third@example.test", ExpectedDirectoryRevision: directory.Revision, Source: "127.0.0.1"}, false); !errors.Is(err, accountdomain.ErrLimited) {
		t.Fatalf("LOGIN to ADD bypassed owner cooldown: %v", err)
	}
	if _, err = f.accounts.BeginCampus(t.Context(), f.owner.SessionToken, uuid.NewString(), "campus@whut.edu.cn", "127.0.0.1"); !errors.Is(err, accountdomain.ErrLimited) {
		t.Fatalf("campus alias bypassed shared cooldown: %v", err)
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
	registered, e := f.beginRegistration(t, registrationKey, b.Email)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.completeRegistration(t, registrationKey, registered); e != nil {
		t.Fatal(e)
	}
	sig := loginSignature(t, key, c)
	if _, e = f.login.Complete(t.Context(), c.OperationID, "00005678", sig, "127.0.0.1"); !errors.Is(e, d.ErrFailed) {
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
			_, e := f.login.Complete(t.Context(), valid.OperationID, "99999999", sig, "127.0.0.1")
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
	result, e := f.login.Complete(t.Context(), c.OperationID, "00005678", sig, "127.0.0.1")
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
			a, e := f.login.Complete(t.Context(), c.OperationID, "00005678", sig, "127.0.0.1")
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
			if _, e := f.login.Complete(t.Context(), op.c.OperationID, "00005678", op.sig, "127.0.0.1"); e != nil {
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
	a, e := service.Complete(ctx, c.OperationID, "00005678", loginSignature(t, key, c), "127.0.0.1")
	cancel()
	if !errors.Is(e, d.ErrUnavailable) || a.SessionToken != "" {
		t.Fatal("unknown commit released token", e)
	}
	disable()
	if _, e = service.Complete(t.Context(), c.OperationID, "00005678", loginSignature(t, key, c), "127.0.0.1"); e != nil && !errors.Is(e, d.ErrCompleted) {
		t.Fatal(e)
	}
}

func TestEmailLoginCrossAccountRevokedAndCompetingRegistration(t *testing.T) {
	f := newEmailLoginFixture(t)
	otherKey := newSigningKey(t)
	registered, e := f.beginRegistration(t, otherKey, "other@example.test")
	if e != nil {
		t.Fatal(e)
	}
	other, e := f.completeRegistration(t, otherKey, registered)
	if e != nil {
		t.Fatal(e)
	}
	clearMailCooldown(t, f)
	cross, e := f.login.Begin(t.Context(), loginBegin(otherKey, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.login.Complete(t.Context(), cross.OperationID, "99999999", loginSignature(t, otherKey, cross), "127.0.0.1"); !errors.Is(e, d.ErrFailed) {
		t.Fatal("conflict disclosed before proofs", e)
	}
	if _, e = f.login.Complete(t.Context(), cross.OperationID, "00005678", loginSignature(t, otherKey, cross), "127.0.0.1"); !errors.Is(e, d.ErrCredential) {
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
	if _, e = f.login.Complete(t.Context(), revoked.OperationID, "00005678", loginSignature(t, otherKey, revoked), "127.0.0.1"); !errors.Is(e, d.ErrCredential) {
		t.Fatal("revoked public key revived", e)
	}
	clearMailCooldown(t, f)
	key := newSigningKey(t)
	c, e := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	reg, e := f.beginRegistration(t, key, "competing@example.test")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, e := f.login.Complete(t.Context(), c.OperationID, "00005678", loginSignature(t, key, c), "127.0.0.1")
		results <- e
	}()
	go func() {
		defer wg.Done()
		_, e := f.completeRegistration(t, key, reg)
		results <- e
	}()
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		} else if !errors.Is(e, d.ErrCredential) && !errors.Is(e, accountdomain.ErrCredential) && !errors.Is(e, regport.ErrCredentialRegistered) && !errors.Is(e, ap.ErrCredentialRegistered) {
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
func TestEmailLoginRestartDoesNotCloseOperation(t *testing.T) {
	f := newEmailLoginFixture(t)
	clearMailCooldown(t, f)
	key := newSigningKey(t)
	c, e := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.lr.Initialize(t.Context(), time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = f.login.Complete(t.Context(), c.OperationID, "00005678", loginSignature(t, key, c), "127.0.0.1"); e != nil {
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
	directory := f.addForSwitch(t, "replacement@example.test")
	var result auth.Established
	var loginErr, bindErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		result, loginErr = f.login.Complete(t.Context(), challenge.OperationID, "00005678", loginSignature(t, key, challenge), "127.0.0.1")
	}()
	go func() {
		defer wg.Done()
		bindErr = f.switchEmail(t, directory, "replacement@example.test")
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
	current, e := f.accounts.Own(t.Context(), f.owner.SessionToken, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if e = f.switchEmail(t, current, "login@example.test"); e != nil {
		t.Fatal(e)
	}
	_, e = f.login.Complete(t.Context(), challenge.OperationID, "00005678", loginSignature(t, key, challenge), "127.0.0.1")
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
	if _, e = f.db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.owner.AuthID}, bson.M{"$set": bson.M{"accountStatus": "ACTIVE", "accountRevision": int64(1)}}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.login.Complete(t.Context(), challenge.OperationID, "00005678", loginSignature(t, key, challenge), "127.0.0.1"); !errors.Is(e, d.ErrFailed) {
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
