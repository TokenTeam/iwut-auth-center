package mongo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/adapter/emailaccountprotocol"
	"iwut-auth-center/internal/adapter/passwordcrypto"
	auth "iwut-auth-center/internal/authentication/domain"
	authusecase "iwut-auth-center/internal/authentication/usecase"
	d "iwut-auth-center/internal/emailaccount/domain"
	"iwut-auth-center/internal/emailaccount/usecase"
	pwd "iwut-auth-center/internal/password/domain"
)

type accountMail struct {
	code  string
	calls int
}

func (m *accountMail) Send(_ context.Context, _, _, code string, _ time.Time) error {
	m.code = code
	m.calls++
	return nil
}

type emailAccountFixture struct {
	auth    *AuthenticationRepository
	repo    *EmailAccountRepository
	service *usecase.Service
	device  *deviceprotocol.Protocol
	mail    *accountMail
	key     *ecdsa.PrivateKey
	clock   time.Time
}

func newEmailAccountFixture(t *testing.T) *emailAccountFixture {
	t.Helper()
	db := integrationDatabase(t)
	for _, err := range []error{EnsurePrincipalSchema(t.Context(), db), EnsureAuthenticationSchema(t.Context(), db), EnsurePasswordSchema(t.Context(), db), EnsurePasswordQuotaSchema(t.Context(), db), EnsureEmailAccountSchema(t.Context(), db)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	a, err := NewAuthenticationRepository(db, 10000, 5)
	if err != nil {
		t.Fatal(err)
	}
	device, _ := deviceprotocol.New("iwut-auth-center:test")
	protocol, _ := emailaccountprotocol.New(bytes32(21), bytes32(22), "iwut-auth-center:test")
	pwdProtocol, _ := passwordcrypto.NewProtocol(bytes32(22), "iwut-auth-center:test")
	passwords, _ := NewPasswordRepository(a, pwdProtocol.KeyID())
	quota, _ := NewPasswordQuota(a)
	r, err := NewEmailAccountRepository(&RegistrationRepository{AuthenticationRepository: a, db: db}, passwords, protocol.KeyID(), EmailLimits{OwnerHourly: 1000, EmailHourly: 1000, SourceHourly: 1000, MaxBuckets: 10000})
	if err != nil {
		t.Fatal(err)
	}
	mail := &accountMail{}
	service, err := usecase.New(r, protocol, device, passwordEngine(t, pwd.DefaultParameters()), quota, mail, "iwut-auth-center:test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := &emailAccountFixture{a, r, service, device, mail, key, time.Now().UTC().Truncate(time.Millisecond)}
	a.clock = func() time.Time { return f.clock }
	return f
}
func strings64(s string) string {
	out := ""
	for i := 0; i < 64; i++ {
		out += s
	}
	return out
}
func (f *emailAccountFixture) register(t *testing.T, email string) auth.Established {
	t.Helper()
	public := elliptic.Marshal(f.key.Curve, f.key.X, f.key.Y)
	started, err := f.service.Begin(t.Context(), "", d.Begin{RequestID: uuid.NewString(), Email: email, DeviceVersion: auth.ProtocolVersion, PublicKey: public, Source: "127.0.0.1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.service.Complete(t.Context(), "", started.Operation.OperationID, f.mail.code, initialPassword, signAuthentication(t, f.key, started.SigningPayload), true, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Registration == nil {
		t.Fatal("no initial Session")
	}
	return *result.Registration
}
func (f *emailAccountFixture) add(t *testing.T, token, address string) d.Directory {
	t.Helper()
	f.clock = f.clock.Add(time.Minute)
	current, err := f.service.Own(t.Context(), token, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	started, err := f.service.Begin(t.Context(), token, d.Begin{RequestID: uuid.NewString(), Email: address, ExpectedDirectoryRevision: current.Revision, Source: "127.0.0.1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.service.Complete(t.Context(), token, started.Operation.OperationID, f.mail.code, "", nil, false, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return result.Directory
}
func TestEmailAccountV3RegistrationDirectoryAndSwitchPreservesSession(t *testing.T) {
	f := newEmailAccountFixture(t)
	session := f.register(t, "owner@whut.edu.cn")
	ctx := t.Context()
	current, err := f.service.Own(ctx, session.SessionToken, "127.0.0.1")
	if err != nil || current.Revision != 1 || current.LoginRoleRevision != 1 || len(current.Bindings) != 1 {
		t.Fatal(current, err)
	}
	initial := current.Bindings[0]
	current = f.add(t, session.SessionToken, "other@example.test")
	if current.LoginRoleRevision != 1 || current.LoginBindingID != initial.BindingID || current.Revision != 2 {
		t.Fatal("add changed primary role")
	}
	target := ""
	for _, b := range current.Bindings {
		if b.Email == "other@example.test" {
			target = b.BindingID
		}
	}
	request := d.Mutation{RequestID: uuid.NewString(), BindingID: target, Password: initialPassword, ExpectedDirectoryRevision: 2, ExpectedLoginRoleRevision: 1, Source: "127.0.0.1"}
	_, current, err = f.service.Mutate(ctx, session.SessionToken, request, true)
	if err != nil || current.LoginBindingID != target || current.Revision != 3 || current.LoginRoleRevision != 2 {
		t.Fatal("switch failed", err)
	}
	digest, _ := f.device.TokenDigest(session.SessionToken)
	if _, err = f.auth.CheckSession(ctx, digest, f.clock); err != nil {
		t.Fatal("switch kicked existing Session", err)
	}
	primary, role, eligible, err := ResolvePrimaryEmailTx(ctx, f.auth.database, "owner@whut.edu.cn")
	if err != nil || eligible {
		t.Fatal("nonprimary authorized login", primary, role, err)
	}
	_, current, err = f.service.Mutate(ctx, session.SessionToken, d.Mutation{RequestID: uuid.NewString(), BindingID: initial.BindingID, ExpectedDirectoryRevision: 3, Source: "127.0.0.1"}, false)
	if err != nil || len(current.Bindings) != 1 || current.LoginRoleRevision != 2 {
		t.Fatal("remove failed", err)
	}
	if _, _, err = f.service.Mutate(ctx, session.SessionToken, d.Mutation{RequestID: uuid.NewString(), BindingID: target, ExpectedDirectoryRevision: 4, Source: "127.0.0.1"}, false); !errors.Is(err, d.ErrLoginRemoval) {
		t.Fatal("removed primary", err)
	}
}
func TestEmailAccountV3InvalidPasswordAndAuditFailureAreAtomic(t *testing.T) {
	f := newEmailAccountFixture(t)
	public := elliptic.Marshal(f.key.Curve, f.key.X, f.key.Y)
	start, err := f.service.Begin(t.Context(), "", d.Begin{RequestID: uuid.NewString(), Email: "new@example.test", DeviceVersion: auth.ProtocolVersion, PublicKey: public, Source: "127.0.0.1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	signature := signAuthentication(t, f.key, start.SigningPayload)
	if _, err = f.service.Complete(t.Context(), "", start.Operation.OperationID, f.mail.code, "short", signature, true, "127.0.0.1"); err == nil {
		t.Fatal("missing password accepted")
	}
	if _, err = f.auth.database.Collection(EmailAuditCollection).InsertOne(t.Context(), bson.M{"operationId": start.Operation.OperationID}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Complete(t.Context(), "", start.Operation.OperationID, f.mail.code, initialPassword, signature, true, "127.0.0.1"); err == nil {
		t.Fatal("audit failure committed")
	}
	for _, col := range []string{PrincipalCollection, PasswordCollection, CredentialCollection, SessionCollection, EmailDirectoryCollection, EmailBindingCollection} {
		n, err := f.auth.database.Collection(col).CountDocuments(t.Context(), bson.M{})
		if err != nil || n != 0 {
			t.Fatal("partial registration", col, n, err)
		}
	}
}
func TestEmailAccountV3DeviceLoginAfterRegistration(t *testing.T) {
	f := newEmailAccountFixture(t)
	original := f.register(t, "plain@example.test")
	limiter, _ := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 1000, CompleteGlobal: 1000, BeginSource: 1000, CompleteLocator: 1000, MaxBuckets: 10000})
	login, _ := authusecase.NewLogin(f.auth, f.device, limiter, "iwut-auth-center:test", time.Hour)
	start, err := login.Begin(t.Context(), auth.Locator{Kind: auth.CredentialIDLocator, Value: []byte(original.CredentialID)}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := login.Complete(t.Context(), start.OperationID, signAuthentication(t, f.key, start.SigningPayload))
	if err != nil || result.AuthID != original.AuthID {
		t.Fatal("device login changed", err)
	}
}

func TestEmailAccountV3TenBindingsAndGlobalOwnership(t *testing.T) {
	f := newEmailAccountFixture(t)
	owner := f.register(t, "owner@example.test")
	for i := 1; i < 10; i++ {
		directory := f.add(t, owner.SessionToken, fmt.Sprintf("member%d@example.test", i))
		if len(directory.Bindings) != i+1 {
			t.Fatal("binding count", directory)
		}
	}
	if _, err := f.service.Begin(t.Context(), owner.SessionToken, d.Begin{RequestID: uuid.NewString(), Email: "eleventh@example.test", ExpectedDirectoryRevision: 10, Source: "127.0.0.1"}, false); !errors.Is(err, d.ErrBindingLimit) {
		t.Fatal("eleventh accepted", err)
	}
	// A different account proves both email and its private key, but cannot gain
	// an address already owned as a non-login binding by the first account.
	f.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	public := elliptic.Marshal(f.key.Curve, f.key.X, f.key.Y)
	start, err := f.service.Begin(t.Context(), "", d.Begin{RequestID: uuid.NewString(), Email: "member1@example.test", DeviceVersion: auth.ProtocolVersion, PublicKey: public, Source: "127.0.0.2"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Complete(t.Context(), "", start.Operation.OperationID, f.mail.code, initialPassword, signAuthentication(t, f.key, start.SigningPayload), true, "127.0.0.2"); !errors.Is(err, d.ErrOccupied) {
		t.Fatal("shared campus/non-login address accepted", err)
	}
}

func TestEmailAccountV3ConcurrentSwitchAndIdempotentCurrentState(t *testing.T) {
	f := newEmailAccountFixture(t)
	owner := f.register(t, "owner@example.test")
	directory := f.add(t, owner.SessionToken, "target@example.test")
	target := ""
	for _, b := range directory.Bindings {
		if b.Email == "target@example.test" {
			target = b.BindingID
		}
	}
	first := d.Mutation{RequestID: uuid.NewString(), BindingID: target, Password: initialPassword, ExpectedDirectoryRevision: 2, ExpectedLoginRoleRevision: 1, Source: "127.0.0.1"}
	second := first
	second.RequestID = uuid.NewString()
	requests := []d.Mutation{first, second}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = f.service.Mutate(t.Context(), owner.SessionToken, requests[i], true)
		}(i)
	}
	wg.Wait()
	winner := 0
	if errs[0] != nil {
		winner = 1
	}
	if errs[winner] != nil || !errors.Is(errs[1-winner], d.ErrDirectoryConflict) {
		t.Fatal("CAS did not serialize", errs)
	}
	if _, out, err := f.service.Mutate(t.Context(), owner.SessionToken, requests[winner], true); err != nil || out.Revision != 3 || out.LoginRoleRevision != 2 {
		t.Fatal("replay changed role", out, err)
	}
	next := requests[winner]
	next.RequestID = uuid.NewString()
	next.ExpectedDirectoryRevision = 3
	next.ExpectedLoginRoleRevision = 2
	if _, out, err := f.service.Mutate(t.Context(), owner.SessionToken, next, true); err != nil || out.Revision != 3 {
		t.Fatal("password-verified primary no-op", out, err)
	}
	if _, _, err := f.service.Mutate(t.Context(), owner.SessionToken, d.Mutation{RequestID: uuid.NewString(), BindingID: directory.LoginBindingID, ExpectedDirectoryRevision: 3, Source: "127.0.0.1"}, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.service.Mutate(t.Context(), owner.SessionToken, requests[winner], true); !errors.Is(err, d.ErrDirectoryConflict) {
		t.Fatal("historical response became current", err)
	}
}
