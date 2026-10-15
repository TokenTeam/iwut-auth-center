package mongo

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/campusprotocol"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	d "iwut-auth-center/internal/campuscertification/domain"
	"iwut-auth-center/internal/campuscertification/port"
	uc "iwut-auth-center/internal/campuscertification/usecase"
	email "iwut-auth-center/internal/emailbinding/domain"
	emailport "iwut-auth-center/internal/emailbinding/port"
	rp "iwut-auth-center/internal/registration/port"
	"os"
	"sync"
	"testing"
	"time"
)

type fixedCampusProtocol struct{ *campusprotocol.Protocol }

func (fixedCampusProtocol) NewCode() (string, error) { return "00005678", nil }

type campusFixture struct {
	db            *m.Database
	repo          *CampusCertificationRepository
	protocol      fixedCampusProtocol
	device        *deviceprotocol.Protocol
	digest        []byte
	authID, token string
	now           time.Time
}

func newCampusFixture(t *testing.T) *campusFixture {
	t.Helper()
	uri := os.Getenv("MONGODB_INTEGRATION_URI")
	if uri == "" {
		t.Skip("MONGODB_INTEGRATION_URI is required")
	}
	client, err := m.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	db := client.Database("uc031_" + uuid.NewString())
	t.Cleanup(func() { _ = db.Drop(context.Background()); _ = client.Disconnect(context.Background()) })
	for _, ensure := range []func(context.Context, *m.Database) error{EnsurePrincipalSchema, EnsureAuthenticationSchema, EnsureCampusSchema, EnsureEmailSchema} {
		if err = ensure(t.Context(), db); err != nil {
			t.Fatal(err)
		}
	}
	ar, err := NewAuthenticationRepository(db, 1000, 5)
	if err != nil {
		t.Fatal(err)
	}
	rr, err := NewRegistrationRepository(db, ar)
	if err != nil {
		t.Fatal(err)
	}
	device, _ := deviceprotocol.New("iwut-auth-center:test")
	p, _ := campusprotocol.New(bytes.Repeat([]byte{7}, 32), "iwut-auth-center:test")
	repo, err := NewCampusCertificationRepository(rr, p.KeyID(), EmailLimits{5, 5, 20, 1000})
	if err != nil {
		t.Fatal(err)
	}
	f := &campusFixture{db: db, repo: repo, protocol: fixedCampusProtocol{p}, device: device, now: time.Now().UTC().Truncate(time.Millisecond)}
	ar.clock = func() time.Time { return f.now }
	if err = repo.Initialize(t.Context(), f.now); err != nil {
		t.Fatal(err)
	}
	f.authID, f.token, f.digest = campusFixtureAccount(t, f, "")
	return f
}
func campusFixtureAccount(t *testing.T, f *campusFixture, id string) (string, string, []byte) {
	t.Helper()
	if id == "" {
		id = uuid.NewString()
	}
	key := newSigningKey(t)
	public := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	fingerprint, err := f.device.Fingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	token, digest, err := f.device.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	credentialID := uuid.NewString()
	commit := rp.RegistrationCommit{Credential: auth.Credential{CredentialRevision: 1, CredentialID: credentialID, AuthID: id, ProtocolVersion: auth.ProtocolVersion, PublicKey: public, Fingerprint: fingerprint, CreatedAt: f.now}, Session: auth.Session{SessionID: uuid.NewString(), AuthID: id, CredentialID: credentialID, TokenDigest: digest, AuthenticationMethod: "DEVICE_CREDENTIAL", AuthenticatedAt: f.now, CreatedAt: f.now, LastUsedAt: f.now, ExpiresAt: f.now.Add(48 * time.Hour)}}
	err = f.repo.WithAuthTransaction(t.Context(), func(tx context.Context) error { return f.repo.CreateRegisteredUserTx(tx, commit, f.now) })
	if err != nil {
		t.Fatal(err)
	}
	return id, token, digest
}
func (f *campusFixture) operation(emailAddress string) port.Operation {
	b := d.Begin{RequestID: uuid.NewString(), Email: emailAddress}
	op := port.Operation{Proof: auth.Operation{OperationID: uuid.NewString(), Purpose: d.Purpose, ServiceID: "iwut-auth-center:test", ApplicationID: auth.ApplicationID, AuthID: f.authID, AccountRevision: 1, CreatedAt: f.now, ExpiresAt: f.now.Add(10 * time.Minute), Acceptable: true, Status: auth.Pending}, RequestID: b.RequestID, Email: emailAddress, KeyID: f.protocol.KeyID(), ResendAfter: f.now.Add(time.Minute), RetainUntil: f.now.Add(24 * time.Hour), RequestMAC: f.protocol.RequestMAC(b, f.authID, 1)}
	op.CodeMAC = f.protocol.CodeMAC(op, "00005678")
	return op
}
func campusBegin(t *testing.T, f *campusFixture) port.Operation {
	t.Helper()
	op := f.operation("member@whut.edu.cn")
	saved, fresh, err := f.repo.Begin(t.Context(), op, f.digest, "controlled-peer", f.now)
	if err != nil || !fresh {
		t.Fatal("campus Begin", fresh, err)
	}
	return saved
}
func TestCampusCertificationMongoReplayConcurrencyAndPrivacy(t *testing.T) {
	f := newCampusFixture(t)
	if _, err := f.repo.Own(t.Context(), f.digest, f.now); !errors.Is(err, d.ErrNotFound) {
		t.Fatal("absent fact not distinguished", err)
	}
	op := campusBegin(t, f)
	replay, fresh, err := f.repo.Begin(t.Context(), op, f.digest, "controlled-peer", f.now)
	if err != nil || fresh || replay.Proof.OperationID != op.Proof.OperationID {
		t.Fatal("idempotent Begin", err)
	}
	changed := op
	changed.Email = "other@whut.edu.cn"
	changed.RequestMAC = f.protocol.RequestMAC(d.Begin{RequestID: changed.RequestID, Email: changed.Email}, f.authID, 1)
	if _, _, err = f.repo.Begin(t.Context(), changed, f.digest, "controlled-peer", f.now); !errors.Is(err, d.ErrConflict) {
		t.Fatal("changed idempotency input", err)
	}
	var wg sync.WaitGroup
	results := make(chan d.Certification, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fact, err := f.repo.Complete(t.Context(), op, f.digest, f.now)
			results <- fact
			failures <- err
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("concurrent/replayed Complete", err)
		}
	}
	for fact := range results {
		if !fact.Valid() || !fact.CertifiedAt.Equal(f.now) {
			t.Fatal("immutable first fact", fact)
		}
	}
	for _, collection := range []string{CampusCertificationCollection, CampusAuditCollection} {
		count, err := f.db.Collection(collection).CountDocuments(t.Context(), bson.M{"authId": f.authID})
		if err != nil || count != 1 {
			t.Fatal("duplicate fact/audit", collection, count, err)
		}
	}
	var fact bson.M
	if err = f.db.Collection(CampusCertificationCollection).FindOne(t.Context(), bson.M{"authId": f.authID}).Decode(&fact); err != nil {
		t.Fatal(err)
	}
	if len(fact) != 4 || fact["email"] != nil || fact["fingerprint"] != nil {
		t.Fatal("fact stored unnecessary personal data", fact)
	}
	count, err := f.db.Collection(EmailBindingCollection).CountDocuments(t.Context(), bson.M{"authId": f.authID})
	if err != nil || count != 0 {
		t.Fatal("campus certification changed login binding", err)
	}
	if _, _, err = f.repo.Begin(t.Context(), f.operation("another@whut.edu.cn"), f.digest, "controlled-peer", f.now); !errors.Is(err, d.ErrCertified) {
		t.Fatal("certified Begin sent another code", err)
	}
	wrong := op
	wrong.CodeMAC = f.protocol.CodeMAC(op, "00005679")
	if _, err = f.repo.Complete(t.Context(), wrong, f.digest, f.now); !errors.Is(err, d.ErrVerification) {
		t.Fatal("completed wrong-code replay", err)
	}
	_, _, otherDigest := campusFixtureAccount(t, f, "")
	if _, err = f.repo.Complete(t.Context(), op, otherDigest, f.now); !errors.Is(err, d.ErrVerification) {
		t.Fatal("another account claimed fact", err)
	}
}
func TestCampusCertificationMongoFailuresExpiryAndCurrentGate(t *testing.T) {
	for _, scenario := range []string{"attempts", "expiry", "session", "account_revision", "disabled", "proof_purpose"} {
		t.Run(scenario, func(t *testing.T) {
			f := newCampusFixture(t)
			op := campusBegin(t, f)
			switch scenario {
			case "attempts":
				wrong := op
				wrong.CodeMAC = f.protocol.CodeMAC(op, "11111111")
				for i := 0; i < 5; i++ {
					if _, err := f.repo.Complete(t.Context(), wrong, f.digest, f.now); !errors.Is(err, d.ErrVerification) {
						t.Fatal(err)
					}
				}
				stored, err := f.repo.Get(t.Context(), op.Proof.OperationID)
				if err != nil || stored.Proof.FailedAttempts != 5 || stored.Proof.Status != auth.Closed {
					t.Fatal("attempt exhaustion not committed", stored, err)
				}
			case "expiry":
				// Use a stale caller timestamp: the repository clock wins at final commit.
				f.now = op.Proof.ExpiresAt
			case "session":
				_, err := f.db.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"tokenDigest": f.digest}, bson.M{"$set": bson.M{"revokedAt": f.now}})
				if err != nil {
					t.Fatal(err)
				}
			case "account_revision":
				_, err := f.db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.authID}, bson.M{"$set": bson.M{"accountRevision": int64(2)}})
				if err != nil {
					t.Fatal(err)
				}
			case "disabled":
				_, err := f.db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.authID}, bson.M{"$set": bson.M{"accountStatus": "DISABLED", "accountRevision": int64(2)}})
				if err != nil {
					t.Fatal(err)
				}
			case "proof_purpose":
				_, err := f.db.Collection(AuthenticationOperationCollection).UpdateOne(t.Context(), bson.M{"operationId": op.Proof.OperationID}, bson.M{"$set": bson.M{"purpose": email.BindingPurpose}})
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.repo.Complete(t.Context(), op, f.digest, op.Proof.CreatedAt); err == nil {
				t.Fatal("invalid proof/gate accepted")
			}
			count, err := f.db.Collection(CampusCertificationCollection).CountDocuments(t.Context(), bson.M{})
			if err != nil || count != 0 {
				t.Fatal("failed operation minted fact", err)
			}
		})
	}
}
func TestCampusCertificationMongoReplacementQuotaAndKeyRotation(t *testing.T) {
	f := newCampusFixture(t)
	first := campusBegin(t, f)
	second := f.operation("second@whut.edu.cn")
	if _, _, err := f.repo.Begin(t.Context(), second, f.digest, "controlled-peer", f.now); !errors.Is(err, d.ErrRate) {
		t.Fatal("owner cooldown bypassed", err)
	}
	stored, err := f.repo.Get(t.Context(), first.Proof.OperationID)
	if err != nil || stored.Proof.Status != auth.Pending {
		t.Fatal("failed Begin superseded old code", err)
	}
	f.now = f.now.Add(61 * time.Second)
	second = f.operation("second@whut.edu.cn")
	if _, fresh, err := f.repo.Begin(t.Context(), second, f.digest, "controlled-peer", f.now); err != nil || !fresh {
		t.Fatal(err)
	}
	if _, err = f.repo.Complete(t.Context(), first, f.digest, f.now); !errors.Is(err, d.ErrVerification) {
		t.Fatal("replaced code usable", err)
	}
	rotated, _ := campusprotocol.New(bytes.Repeat([]byte{8}, 32), "iwut-auth-center:test")
	repo, err := NewCampusCertificationRepository(f.repo.RegistrationRepository, rotated.KeyID(), f.repo.limits)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Initialize(t.Context(), f.now); err != nil {
		t.Fatal(err)
	}
	stored, err = repo.Get(t.Context(), second.Proof.OperationID)
	if err != nil || stored.Proof.Status != auth.Closed {
		t.Fatal("key rotation preserved pending code", err)
	}
	f.now = f.now.Add(61 * time.Second)
	replayed := f.operation("second@whut.edu.cn")
	replayed.RequestID = second.RequestID
	replayed.KeyID = rotated.KeyID()
	replayed.RequestMAC = rotated.RequestMAC(d.Begin{RequestID: replayed.RequestID, Email: replayed.Email}, f.authID, 1)
	replayed.CodeMAC = rotated.CodeMAC(replayed, "00005678")
	if _, _, err = repo.Begin(t.Context(), replayed, f.digest, "controlled-peer", f.now); !errors.Is(err, d.ErrVerification) {
		t.Fatal("key rotation evaded idempotency window", err)
	}
	count, err := f.db.Collection(CampusVerificationCollection).CountDocuments(t.Context(), bson.M{"authId": f.authID, "requestId": second.RequestID})
	if err != nil || count != 1 {
		t.Fatal("rotation deleted request identity", count, err)
	}
}
func TestCampusCertificationMongoSharesBindingOwnerAndAddressQuotas(t *testing.T) {
	f := newCampusFixture(t)
	emailRepo, err := NewEmailRepository(f.repo.RegistrationRepository, "email-key", EmailLimits{5, 5, 20, 1000})
	if err != nil {
		t.Fatal(err)
	}
	op := emailport.Operation{Proof: auth.Operation{OperationID: uuid.NewString(), Purpose: email.BindingPurpose, AuthID: f.authID, CreatedAt: f.now, ExpiresAt: f.now.Add(10 * time.Minute), Status: auth.Pending}, RequestID: uuid.NewString(), Owner: f.authID, Mode: email.Bind, Email: "login@example.test", KeyID: "email-key", RequestMAC: bytes.Repeat([]byte{2}, 32), CodeMAC: bytes.Repeat([]byte{3}, 32), ResendAfter: f.now.Add(time.Minute), RetainUntil: f.now.Add(24 * time.Hour)}
	if _, _, err = emailRepo.Begin(t.Context(), op, f.digest, "controlled-peer", f.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.repo.Begin(t.Context(), f.operation("campus@whut.edu.cn"), f.digest, "controlled-peer", f.now); !errors.Is(err, d.ErrRate) {
		t.Fatal("BIND/campus owner quota split", err)
	}
	f.now = f.now.Add(61 * time.Second)
	if _, _, err = f.repo.Begin(t.Context(), f.operation("campus@whut.edu.cn"), f.digest, "controlled-peer", f.now); err != nil {
		t.Fatal(err)
	}
	_, _, secondDigest := campusFixtureAccount(t, f, "")
	otherSession, err := f.repo.CheckSession(t.Context(), secondDigest, f.now)
	if err != nil {
		t.Fatal(err)
	}
	other := f.operation("campus@whut.edu.cn")
	other.Proof.AuthID = otherSession.AuthID
	other.RequestMAC = f.protocol.RequestMAC(d.Begin{RequestID: other.RequestID, Email: other.Email}, otherSession.AuthID, 1)
	other.CodeMAC = f.protocol.CodeMAC(other, "00005678")
	if _, _, err = f.repo.Begin(t.Context(), other, secondDigest, "other-source", f.now); !errors.Is(err, d.ErrRate) {
		t.Fatal("address cooldown split", err)
	}
}
func TestCampusCertificationMongoMalformedFactAndAuditRollback(t *testing.T) {
	f := newCampusFixture(t)
	op := campusBegin(t, f)
	// An incompatible audit schema must roll back both the fact and consumption.
	if err := f.db.Collection(CampusAuditCollection).Drop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.db.RunCommand(t.Context(), bson.D{{Key: "create", Value: CampusAuditCollection}, {Key: "validator", Value: bson.M{"mustExist": bson.M{"$exists": true}}}, {Key: "validationAction", Value: "error"}}).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.Complete(t.Context(), op, f.digest, f.now); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("audit failure returned success", err)
	}
	if _, err := ReadCampusCertificationTx(t.Context(), f.db, f.authID); !errors.Is(err, d.ErrNotFound) {
		t.Fatal("audit failure retained fact", err)
	}
	stored, err := f.repo.Get(t.Context(), op.Proof.OperationID)
	if err != nil || stored.Proof.Status != auth.Pending {
		t.Fatal("audit failure consumed operation", stored, err)
	}
	for _, bad := range []bson.M{{"authId": f.authID, "institution": "WHUT"}, {"authId": f.authID, "institution": "STUDENT", "certifiedAt": f.now}, {"authId": f.authID, "institution": "WHUT", "certifiedAt": f.now, "email": "private@whut.edu.cn"}, {"authId": f.authID, "institution": "WHUT", "certifiedAt": "not-an-instant"}} {
		if _, err = f.db.Collection(CampusCertificationCollection).InsertOne(t.Context(), bad); err != nil {
			t.Fatal(err)
		}
		if _, err = ReadCampusCertificationTx(t.Context(), f.db, f.authID); !errors.Is(err, d.ErrUnavailable) {
			t.Fatal("bad fact treated as absent/valid", err)
		}
		if _, err = f.db.Collection(CampusCertificationCollection).DeleteMany(t.Context(), bson.M{"authId": f.authID}); err != nil {
			t.Fatal(err)
		}
	}
}
func TestCampusCertificationMongoUsecaseDeliveryAndNormalization(t *testing.T) {
	f := newCampusFixture(t)
	sender := &emailCapture{}
	limiter, _ := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 10000, CompleteGlobal: 10000, BeginSource: 10000, CompleteLocator: 10000, MaxBuckets: 10000})
	service, err := uc.New(f.repo, f.protocol, f.device, sender, limiter, "iwut-auth-center:test")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := service.Authorize(t.Context(), f.token)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"user@example.test", "user@other.whut.edu.cn", "user@whut.edu.cn.evil.test", "user@whut.edu.cn\n"} {
		if _, err = service.Begin(t.Context(), d.Begin{RequestID: uuid.NewString(), Email: address, Source: "source"}, digest); !errors.Is(err, d.ErrInvalid) {
			t.Fatal("invalid campus address", address, err)
		}
	}
	b := d.Begin{RequestID: uuid.NewString(), Email: "  Member+Tag@WHUT.EDU.CN  ", Source: "controlled-peer"}
	sender.fail = true
	if _, err = service.Begin(t.Context(), b, digest); !errors.Is(err, d.ErrDelivery) {
		t.Fatal("delivery failure not surfaced", err)
	}
	sender.fail = false
	op, err := service.Begin(t.Context(), b, digest)
	if err != nil || sender.count != 1 || op.Email != "member+tag@whut.edu.cn" {
		t.Fatal("idempotent resend/normalization", op.Email, sender.count, err)
	}
	fact, err := service.Complete(t.Context(), op.Proof.OperationID, "00005678", digest)
	if err != nil || !fact.Valid() {
		t.Fatal("valid usecase Complete", fact, err)
	}
	if _, err = service.Complete(t.Context(), op.Proof.OperationID, "00005678", digest); err != nil {
		t.Fatal("response-loss recovery", err)
	}
}

func TestCampusCertificationMongoTransientRetryAndUnknownCommit(t *testing.T) {
	f := newCampusFixture(t)
	fault, appName := sessionRevocationFaultRepository(t, f.db)
	fault.clock = func() time.Time { return f.now }
	registration, err := NewRegistrationRepository(fault.database, fault)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewCampusCertificationRepository(registration, f.protocol.KeyID(), f.repo.limits)
	if err != nil {
		t.Fatal(err)
	}
	admin := f.db.Client().Database("admin")
	disable := func() {
		_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	}
	t.Cleanup(disable)
	if err = admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: bson.M{"times": 1}}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"insert"}, "errorCode": 112, "errorLabels": bson.A{"TransientTransactionError"}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	op := f.operation("member@whut.edu.cn")
	saved, fresh, err := repo.Begin(t.Context(), op, f.digest, "controlled-peer", f.now)
	if err != nil || !fresh {
		t.Fatal("transient Begin failed", err)
	}
	count, err := f.db.Collection(CampusVerificationCollection).CountDocuments(t.Context(), bson.M{"authId": f.authID})
	if err != nil || count != 1 {
		t.Fatal("transaction retry duplicated operation", count, err)
	}
	if err = admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	fact, err := repo.Complete(ctx, saved, f.digest, f.now)
	cancel()
	if !errors.Is(err, d.ErrUnavailable) || fact.Valid() {
		t.Fatal("unknown commit claimed successful certification", fact, err)
	}
	disable()
	// An uncertain result never grants client-side success. Query and a safe
	// replay converge, whether the original commit happened or not.
	_, err = repo.Own(t.Context(), f.digest, f.now)
	if err != nil && !errors.Is(err, d.ErrNotFound) {
		t.Fatal("post-unknown query could not recover", err)
	}
	fact, err = repo.Complete(t.Context(), saved, f.digest, f.now)
	if err != nil || !fact.Valid() {
		t.Fatal("post-unknown completion failed", fact, err)
	}
	count, err = f.db.Collection(CampusCertificationCollection).CountDocuments(t.Context(), bson.M{"authId": f.authID})
	if err != nil || count != 1 {
		t.Fatal("unknown retry duplicated fact", count, err)
	}
}

func TestCampusCertificationMongoExpiryAfterSnapshot(t *testing.T) {
	f := newCampusFixture(t)
	op := campusBegin(t, f)
	calls := 0
	f.repo.clock = func() time.Time {
		calls++
		if calls > 3 {
			return op.Proof.ExpiresAt
		}
		return op.Proof.CreatedAt
	}
	if _, err := f.repo.Complete(t.Context(), op, f.digest, op.Proof.CreatedAt); !errors.Is(err, d.ErrVerification) {
		t.Fatal("proof expired during snapshot reads was accepted", err)
	}
	count, err := f.db.Collection(CampusCertificationCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil || count != 0 {
		t.Fatal("late-expired verification minted fact", count, err)
	}
}
