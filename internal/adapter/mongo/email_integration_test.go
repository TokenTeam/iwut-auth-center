package mongo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/adapter/emailprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	d "iwut-auth-center/internal/emailbinding/domain"
	emailport "iwut-auth-center/internal/emailbinding/port"
	uc "iwut-auth-center/internal/emailbinding/usecase"
	"os"
	"sync"
	"testing"
	"time"
)

type fixedEmailProtocol struct{ *emailprotocol.Protocol }

func (fixedEmailProtocol) NewCode() (string, error) { return "00001234", nil }

type emailCapture struct {
	mu    sync.Mutex
	count int
	fail  bool
}

func (c *emailCapture) Send(context.Context, string, string, string, time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if c.fail {
		return errors.New("rejected")
	}
	return nil
}

type emailFixture struct {
	*registrationFixture
	email   *EmailRepository
	service *uc.Service
	sender  *emailCapture
	ep      fixedEmailProtocol
}

func newEmailFixture(t *testing.T) *emailFixture {
	t.Helper()
	uri := os.Getenv("MONGODB_INTEGRATION_URI")
	if uri == "" {
		t.Skip("MONGODB_INTEGRATION_URI is required")
	}
	client, err := drivermongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	db := client.Database("uc011_" + uuid.NewString())
	t.Cleanup(func() { db.Drop(context.Background()); client.Disconnect(context.Background()) })
	for _, ensure := range []func(context.Context, *drivermongo.Database) error{EnsurePrincipalSchema, EnsureAuthenticationSchema, EnsureCampusSchema} {
		if err = ensure(t.Context(), db); err != nil {
			t.Fatal(err)
		}
	}
	authRepo, err := NewAuthenticationRepository(db, 10000, 5)
	if err != nil {
		t.Fatal(err)
	}
	regRepo, err := NewRegistrationRepository(db, authRepo)
	if err != nil {
		t.Fatal(err)
	}
	device, _ := deviceprotocol.New("iwut-auth-center:test")
	f := &registrationFixture{db: db, repo: regRepo, protocol: device}
	p, _ := emailprotocol.New(bytes.Repeat([]byte{3}, 32), "iwut-auth-center:test")
	ep := fixedEmailProtocol{p}
	repo, e := NewEmailRepository(f.repo, p.KeyID(), EmailLimits{5, 5, 20, 1000})
	if e != nil {
		t.Fatal(e)
	}
	if e = repo.Initialize(t.Context(), time.Now()); e != nil {
		t.Fatal(e)
	}
	sender := &emailCapture{}
	limiter, _ := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 100000, CompleteGlobal: 100000, BeginSource: 100000, CompleteLocator: 100000, MaxBuckets: 10000})
	service, e := uc.New(repo, ep, f.protocol, sender, limiter, "iwut-auth-center:test", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	return &emailFixture{f, repo, service, sender, ep}
}
func emailBegin(key *ecdsa.PrivateKey, email string) d.Begin {
	return d.Begin{RequestID: uuid.NewString(), Mode: d.Register, Email: email, ProtocolVersion: auth.ProtocolVersion, PublicKey: elliptic.Marshal(elliptic.P256(), key.X, key.Y), Source: "controlled-peer"}
}
func emailSignature(t *testing.T, key *ecdsa.PrivateKey, s emailport.Started) []byte {
	t.Helper()
	sum := sha256.Sum256(s.SigningPayload)
	sig, e := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if e != nil {
		t.Fatal(e)
	}
	return sig
}
func completeEmail(t *testing.T, f *emailFixture, key *ecdsa.PrivateKey, s emailport.Started) (emailport.Activated, error) {
	t.Helper()
	return f.service.Complete(t.Context(), s.Operation.Proof.OperationID, "00001234", emailSignature(t, key, s), true, nil)
}
func countEmail(t *testing.T, f *emailFixture, c string) int64 {
	t.Helper()
	n, e := f.db.Collection(c).CountDocuments(t.Context(), bson.M{})
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func TestEmailRegistrationBindingReplayPrivacy(t *testing.T) {
	f := newEmailFixture(t)
	key := newSigningKey(t)
	b := emailBegin(key, "  User+TAG@EXAMPLE.TEST  ")
	s, e := f.service.Begin(t.Context(), b, nil)
	if e != nil {
		t.Fatal(e)
	}
	if countEmail(t, f, PrincipalCollection) != 0 {
		t.Fatal("Begin created account")
	}
	replay, e := f.service.Begin(t.Context(), b, nil)
	if e != nil || replay.Operation.Proof.OperationID != s.Operation.Proof.OperationID || !bytes.Equal(replay.SigningPayload, s.SigningPayload) || f.sender.count != 1 {
		t.Fatalf("begin idempotency: %v", e)
	}
	changed := b
	changed.Email = "different@example.test"
	if _, e = f.service.Begin(t.Context(), changed, nil); !errors.Is(e, d.ErrConflict) {
		t.Fatalf("changed request: %v", e)
	}
	a, e := completeEmail(t, f, key, s)
	if e != nil || a.Registration == nil || a.Revision != 1 {
		t.Fatalf("complete: %v", e)
	}
	for _, c := range []string{PrincipalCollection, CredentialCollection, SessionCollection, EmailBindingCollection, EmailAuditCollection} {
		if n := countEmail(t, f, c); n != 1 {
			t.Fatalf("%s = %d", c, n)
		}
	}
	for _, c := range []string{AssociationCollection, AssociationMemberCollection} {
		if n := countEmail(t, f, c); n != 0 {
			t.Fatalf("retired %s written: %d", c, n)
		}
	}
	if _, e = completeEmail(t, f, key, s); !errors.Is(e, d.ErrCompleted) {
		t.Fatalf("complete replay: %v", e)
	}
	if _, e = f.service.Begin(t.Context(), b, nil); !errors.Is(e, d.ErrCompleted) {
		t.Fatalf("begin replay: %v", e)
	}
	op, e := f.email.Get(t.Context(), s.Operation.Proof.OperationID)
	if e != nil || len(op.Proof.Ciphertext) != 0 || len(op.Proof.LookupKey) != 0 {
		t.Fatal("completed ciphertext retained")
	}
	raw, e := f.db.Collection(EmailAuditCollection).FindOne(t.Context(), bson.M{}).Raw()
	if e != nil || bytes.Contains(raw, []byte("user+tag@example.test")) || bytes.Contains(raw, []byte("00001234")) || bytes.Contains(raw, []byte(a.Registration.SessionToken)) {
		t.Fatal("audit secret leak")
	}
	digest, e := f.service.Authorize(t.Context(), &a.Registration.SessionToken)
	if e != nil {
		t.Fatal(e)
	}
	own, e := f.service.Own(t.Context(), digest)
	if e != nil || own.Email != "user+tag@example.test" || own.Revision != 1 {
		t.Fatalf("query: %+v %v", own, e)
	}
	revision := int64(1)
	binding := d.Begin{RequestID: uuid.NewString(), Mode: d.Bind, Email: "new@example.test", Revision: &revision, Source: "controlled-peer"}
	pending, e := f.service.Begin(t.Context(), binding, digest)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.Complete(t.Context(), pending.Operation.Proof.OperationID, "00001234", nil, false, nil); !errors.Is(e, d.ErrSession) {
		t.Fatalf("BIND became anonymous: %v", e)
	}
	own, e = f.service.Own(t.Context(), digest)
	if e != nil || own.Email != a.Email || own.Pending == nil {
		t.Fatal("old binding not preserved")
	}
	activated, e := f.service.Complete(t.Context(), pending.Operation.Proof.OperationID, "00001234", nil, false, digest)
	if e != nil || activated.Revision != 2 || activated.Registration != nil {
		t.Fatalf("bind: %v", e)
	}
	for range 2 {
		again, e := f.service.Complete(t.Context(), pending.Operation.Proof.OperationID, "00001234", nil, false, digest)
		if e != nil || again.Revision != 2 {
			t.Fatalf("binding idempotency: %v", e)
		}
	}
	if countEmail(t, f, SessionCollection) != 1 || countEmail(t, f, PrincipalCollection) != 1 {
		t.Fatal("binding created session or principal")
	}
	if e = f.repo.RevokeCurrentSession(t.Context(), digest, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.Authorize(t.Context(), &a.Registration.SessionToken); !errors.Is(e, d.ErrSession) {
		t.Fatalf("revoked session: %v", e)
	}
}
func TestEmailConcurrentProofFailuresAndNoPartialAccount(t *testing.T) {
	f := newEmailFixture(t)
	key := newSigningKey(t)
	s, e := f.service.Begin(t.Context(), emailBegin(key, "bad@example.test"), nil)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := f.service.Complete(context.Background(), s.Operation.Proof.OperationID, "99999999", []byte{1}, true, nil)
			if !errors.Is(e, d.ErrVerification) {
				t.Errorf("wrong proof: %v", e)
			}
		}()
	}
	wg.Wait()
	op, e := f.email.Get(t.Context(), s.Operation.Proof.OperationID)
	if e != nil || op.Proof.FailedAttempts != 5 || op.Proof.Status != auth.Closed || len(op.Proof.Ciphertext) != 0 {
		t.Fatalf("unbounded failures: %+v %v", op.Proof, e)
	}
	if _, e = completeEmail(t, f, key, s); !errors.Is(e, d.ErrVerification) {
		t.Fatal("exhausted operation accepted")
	}
	if countEmail(t, f, PrincipalCollection) != 0 {
		t.Fatal("failed proof created user")
	}
}
func TestEmailConcurrentCompletionCredentialUniqueness(t *testing.T) {
	f := newEmailFixture(t)
	key := newSigningKey(t)
	b := emailBegin(key, "race@example.test")
	s, e := f.service.Begin(t.Context(), b, nil)
	if e != nil {
		t.Fatal(e)
	}
	results := make(chan error, 2)
	go func() { _, e := completeEmail(t, f, key, s); results <- e }()
	go func() { _, e := completeEmail(t, f, key, s); results <- e }()
	winners := 0
	for range 2 {
		if e := <-results; e == nil {
			winners++
		}
	}
	if winners != 1 || countEmail(t, f, PrincipalCollection) != 1 || countEmail(t, f, CredentialCollection) != 1 || countEmail(t, f, SessionCollection) != 1 {
		t.Fatal("non-atomic credential uniqueness")
	}
}
func TestEmailRollbackAuditAndRetry(t *testing.T) {
	f := newEmailFixture(t)
	key := newSigningKey(t)
	s, e := f.service.Begin(t.Context(), emailBegin(key, "rollback@example.test"), nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.db.CreateCollection(t.Context(), EmailAuditCollection); e != nil {
		t.Fatal(e)
	}
	if e = f.db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: EmailAuditCollection}, {Key: "validator", Value: bson.M{"impossible": bson.M{"$exists": true}}}}).Err(); e != nil {
		t.Fatal(e)
	}
	if _, e = completeEmail(t, f, key, s); !errors.Is(e, d.ErrUnavailable) {
		t.Fatalf("audit rollback: %v", e)
	}
	for _, c := range []string{PrincipalCollection, CredentialCollection, SessionCollection, AssociationCollection, AssociationMemberCollection, EmailBindingCollection} {
		if countEmail(t, f, c) != 0 {
			t.Fatalf("partial %s", c)
		}
	}
	op, e := f.email.Get(t.Context(), s.Operation.Proof.OperationID)
	if e != nil || op.Proof.Status != auth.Pending {
		t.Fatal("operation consumed on rollback")
	}
	if e = f.db.RunCommand(t.Context(), bson.D{{Key: "collMod", Value: EmailAuditCollection}, {Key: "validator", Value: bson.M{}}}).Err(); e != nil {
		t.Fatal(e)
	}
	if _, e = completeEmail(t, f, key, s); e != nil {
		t.Fatal(e)
	}
}
func TestEmailKeyRotationIndependentOfRetiredAssociation(t *testing.T) {
	f := newEmailFixture(t)
	key := newSigningKey(t)
	b := emailBegin(key, "rotation@example.test")
	s, e := f.service.Begin(t.Context(), b, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.email.Initialize(t.Context(), time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.Begin(t.Context(), b, nil); e != nil {
		t.Fatal("same-key restart invalidated proposal")
	}
	p, _ := emailprotocol.New(bytes.Repeat([]byte{4}, 32), "iwut-auth-center:test")
	rotated, _ := NewEmailRepository(f.repo, p.KeyID(), EmailLimits{5, 5, 20, 1000})
	if e = rotated.Initialize(t.Context(), time.Now()); e != nil {
		t.Fatal(e)
	}
	op, e := f.email.Get(t.Context(), s.Operation.Proof.OperationID)
	if e != nil || op.Proof.Status != auth.Closed || len(op.Proof.Ciphertext) != 0 {
		t.Fatal("HMAC rotation retained proposal")
	}
	// New operation snapshots never contain retired school identity material.
	raw, e := f.db.Collection(AuthenticationOperationCollection).FindOne(t.Context(), bson.M{"operationId": s.Operation.Proof.OperationID}).Raw()
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"schemeVersion", "keyVersion", "lookupKey", "nonce", "ciphertext"} {
		if _, e = raw.LookupErr(field); e == nil {
			t.Fatalf("retired snapshot field %s persisted", field)
		}
	}
}
func TestEmailDeliveryFailureRetainsIdempotencyAndQuota(t *testing.T) {
	f := newEmailFixture(t)
	f.sender.fail = true
	key := newSigningKey(t)
	b := emailBegin(key, "delivery@example.test")
	if _, e := f.service.Begin(t.Context(), b, nil); !errors.Is(e, d.ErrDelivery) {
		t.Fatal(e)
	}
	s, e := f.service.Begin(t.Context(), b, nil)
	if e != nil || s.Operation.Proof.OperationID == "" || f.sender.count != 1 {
		t.Fatalf("retry delivery: %v", e)
	}
	b.RequestID = uuid.NewString()
	if _, e = f.service.Begin(t.Context(), b, nil); !errors.Is(e, d.ErrRate) {
		t.Fatalf("cooldown: %v", e)
	}
	if countEmail(t, f, PrincipalCollection) != 0 {
		t.Fatal("delivery failure created user")
	}
}

func TestEmailUnknownCommitNeverReturnsTokenOrSends(t *testing.T) {
	f := newEmailFixture(t)
	fault, appName := sessionRevocationFaultRepository(t, f.db)
	registration, e := NewRegistrationRepository(fault.database, fault)
	if e != nil {
		t.Fatal(e)
	}
	repo, e := NewEmailRepository(registration, f.ep.KeyID(), EmailLimits{5, 5, 20, 1000})
	if e != nil {
		t.Fatal(e)
	}
	limiter, _ := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 100000, CompleteGlobal: 100000, BeginSource: 100000, CompleteLocator: 100000, MaxBuckets: 10000})
	service, e := uc.New(repo, f.ep, f.protocol, f.sender, limiter, "iwut-auth-center:test", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	admin := f.db.Client().Database("admin")
	enable := func() {
		t.Helper()
		if e := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); e != nil {
			t.Fatal(e)
		}
	}
	disable := func() {
		admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}})
	}
	t.Cleanup(disable)
	key := newSigningKey(t)
	b := emailBegin(key, "unknown@example.test")
	enable()
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	result, e := service.Begin(ctx, b, nil)
	cancel()
	if !errors.Is(e, d.ErrUnavailable) || result.Operation.Proof.OperationID != "" || f.sender.count != 0 {
		t.Fatalf("unknown begin falsely confirmed: %v", e)
	}
	disable()
	started, e := service.Begin(t.Context(), b, nil)
	if e != nil {
		t.Fatal(e)
	}
	signature := emailSignature(t, key, started)
	enable()
	ctx, cancel = context.WithTimeout(t.Context(), 250*time.Millisecond)
	activated, e := service.Complete(ctx, started.Operation.Proof.OperationID, "00001234", signature, true, nil)
	cancel()
	if !errors.Is(e, d.ErrUnavailable) || activated.Registration != nil {
		t.Fatalf("unknown completion leaked success: %v", e)
	}
	disable()
	activated, e = service.Complete(t.Context(), started.Operation.Proof.OperationID, "00001234", signature, true, nil)
	if e != nil && !errors.Is(e, d.ErrCompleted) {
		t.Fatal(e)
	}
	if e == nil && activated.Registration == nil {
		t.Fatal("confirmed commit lost token")
	}
	if countEmail(t, f, PrincipalCollection) != 1 {
		t.Fatal("retry duplicated account")
	}
}
func TestEmailCompetingModesUniqueAddress(t *testing.T) {
	for _, modes := range [][2]string{{d.Register, d.Register}, {d.Register, d.Bind}, {d.Bind, d.Bind}} {
		t.Run(modes[0]+"_"+modes[1], func(t *testing.T) {
			f := newEmailFixture(t)
			type contender struct {
				s                 emailport.Started
				signature, digest []byte
			}
			cases := make([]contender, 2)
			for i, mode := range modes {
				key := newSigningKey(t)
				var digest []byte
				var b d.Begin
				if mode == d.Register {
					b = emailBegin(key, "shared@example.test")
				} else {
					registration, e := f.service.Begin(t.Context(), emailBegin(key, uuid.NewString()+"@example.test"), nil)
					if e != nil {
						t.Fatal(e)
					}
					a, e := completeEmail(t, f, key, registration)
					if e != nil {
						t.Fatal(e)
					}
					digest, _ = f.protocol.TokenDigest(a.Registration.SessionToken)
					revision := int64(1)
					b = d.Begin{Mode: d.Bind, RequestID: uuid.NewString(), Email: "shared@example.test", Revision: &revision, Source: "controlled-peer"}
				}
				f.repo.clock = func() time.Time { return time.Now().Add(time.Duration(i) * 61 * time.Second) }
				s, e := f.service.Begin(t.Context(), b, digest)
				if e != nil {
					t.Fatal(e)
				}
				cases[i] = contender{s: s, digest: digest}
				if mode == d.Register {
					cases[i].signature = emailSignature(t, key, s)
				}
			}
			results := make(chan error, 2)
			for _, c := range cases {
				go func(c contender) {
					_, e := f.service.Complete(context.Background(), c.s.Operation.Proof.OperationID, "00001234", c.signature, c.signature != nil, c.digest)
					results <- e
				}(c)
			}
			winners := 0
			for range 2 {
				e := <-results
				if e == nil {
					winners++
				} else if !errors.Is(e, d.ErrOccupied) {
					t.Fatalf("unexpected conflict: %v", e)
				}
			}
			owned, err := f.db.Collection(EmailBindingCollection).CountDocuments(t.Context(), bson.M{"email": "shared@example.test"})
			if err != nil || winners != 1 || owned != 1 {
				t.Fatal("unique binding violated")
			}
		})
	}
}
func TestEmailSlidingQuotaPersistsAcrossRepositoryRestart(t *testing.T) {
	f := newEmailFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	for i := range 5 {
		at := now.Add(time.Duration(i) * time.Minute)
		if e := f.email.WithAuthTransaction(t.Context(), func(tx context.Context) error { return f.email.debitTx(tx, "email:quota@example.test", 5, true, at) }); e != nil {
			t.Fatal(e)
		}
	}
	restart, _ := NewEmailRepository(f.repo, f.ep.KeyID(), EmailLimits{5, 5, 20, 1000})
	if e := restart.Initialize(t.Context(), now.Add(5*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := restart.WithAuthTransaction(t.Context(), func(tx context.Context) error {
		return restart.debitTx(tx, "email:quota@example.test", 5, true, now.Add(59*time.Minute))
	}); !errors.Is(e, d.ErrRate) {
		t.Fatalf("restart reset quota: %v", e)
	}
	if e := restart.WithAuthTransaction(t.Context(), func(tx context.Context) error {
		return restart.debitTx(tx, "email:quota@example.test", 5, true, now.Add(time.Hour))
	}); e != nil {
		t.Fatalf("sliding first slot not released: %v", e)
	}
	// Existing active buckets cannot be evicted when total capacity is full.
	restart.limits.MaxBuckets = 1
	if e := restart.WithAuthTransaction(t.Context(), func(tx context.Context) error {
		return restart.debitTx(tx, "email:new@example.test", 5, true, now.Add(time.Hour))
	}); !errors.Is(e, d.ErrRate) {
		t.Fatal("active bucket evicted")
	}
}
func TestEmailExpiryAndSupersessionClearSnapshots(t *testing.T) {
	f := newEmailFixture(t)
	key := newSigningKey(t)
	b := emailBegin(key, "first@example.test")
	first, e := f.service.Begin(t.Context(), b, nil)
	if e != nil {
		t.Fatal(e)
	}
	f.repo.clock = func() time.Time { return time.Now().Add(61 * time.Second) }
	b.RequestID = uuid.NewString()
	b.Email = "second@example.test"
	second, e := f.service.Begin(t.Context(), b, nil)
	if e != nil {
		t.Fatal(e)
	}
	old, e := f.email.Get(t.Context(), first.Operation.Proof.OperationID)
	if e != nil || old.Proof.Status != auth.Closed || len(old.Proof.Ciphertext) != 0 {
		t.Fatal("superseded snapshot retained")
	}
	if _, e = completeEmail(t, f, key, first); !errors.Is(e, d.ErrVerification) {
		t.Fatal("old code accepted")
	}
	f.repo.clock = func() time.Time { return second.Operation.Proof.ExpiresAt }
	if _, e = completeEmail(t, f, key, second); !errors.Is(e, d.ErrVerification) {
		t.Fatalf("expiry boundary: %v", e)
	}
	if countEmail(t, f, PrincipalCollection) != 0 {
		t.Fatal("expired proof created user")
	}
}
