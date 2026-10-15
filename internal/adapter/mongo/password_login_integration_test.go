package mongo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/adapter/passwordcrypto"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
	uc "iwut-auth-center/internal/password/usecase"
	"sync"
	"testing"
	"time"
)

type passwordLoginFixture struct {
	passwordFixture
	repo     *PasswordLoginRepository
	protocol *passwordcrypto.Protocol
	service  *uc.LoginService
	clock    time.Time
}

func newPasswordLoginFixture(t *testing.T) *passwordLoginFixture {
	t.Helper()
	f := attachPassword(t, newAuthenticationFixture(t))
	if err := EnsurePasswordLoginSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	protocol, _ := passwordcrypto.NewProtocol(bytes32(11), "iwut-auth-center:test")
	repo, err := NewPasswordLoginRepository(f.repository, protocol)
	if err != nil {
		t.Fatal(err)
	}
	out := &passwordLoginFixture{passwordFixture: f, repo: repo, protocol: protocol, clock: time.Now().UTC().Truncate(time.Millisecond)}
	f.r.clock = func() time.Time { return out.clock }
	out.service = out.newService(t, f.engine)
	return out
}
func (f *passwordLoginFixture) newService(t *testing.T, engine p.RehashEngine) *uc.LoginService {
	t.Helper()
	budget, _ := passwordcrypto.NewAddressBudget(bytes32(19))
	dummy, _ := f.engine.DummyMaterial()
	s, err := uc.NewLoginService(f.repo, engine, f.protocol, f.p, f.quota, budget, dummy, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(func() time.Time { return f.clock })
	return s
}
func passwordLoginKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, elliptic.Marshal(key.Curve, key.X, key.Y)
}
func (f *passwordLoginFixture) beginPassword(t *testing.T, key []byte) auth.Challenge {
	t.Helper()
	o, err := f.service.Begin(t.Context(), uuid.NewString(), "primary@example.test", auth.ProtocolVersion, key, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func TestPasswordLoginNewReuseReplayAndRecovery(t *testing.T) {
	f := newPasswordLoginFixture(t)
	key, public := passwordLoginKey(t)
	request := uuid.NewString()
	o, err := f.service.Begin(t.Context(), request, "Primary@EXAMPLE.TEST", auth.ProtocolVersion, public, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	prior, err := f.service.Begin(t.Context(), request, "primary@example.test", auth.ProtocolVersion, public, "127.0.0.1")
	if err != nil || prior.OperationID != o.OperationID || !prior.ExpiresAt.Equal(o.ExpiresAt) {
		t.Fatal(prior, err)
	}
	_, different := passwordLoginKey(t)
	if _, err = f.service.Begin(t.Context(), request, "primary@example.test", auth.ProtocolVersion, different, "127.0.0.1"); !errors.Is(err, d.ErrRequestConflict) {
		t.Fatal("different proposal", err)
	}
	if n, _ := f.r.database.Collection(CredentialCollection).CountDocuments(t.Context(), bson.M{}); n != 1 {
		t.Fatal("Begin registered key", n)
	}
	sig := signAuthentication(t, key, o.SigningPayload)
	result, err := f.service.Complete(t.Context(), o.OperationID, initialPassword, sig, "127.0.0.1")
	if err != nil || result.AuthID != f.c.AuthID || result.SessionToken == "" {
		t.Fatal(result, err)
	}
	session, err := f.u.Check(t.Context(), result.SessionToken)
	if err != nil || session.AuthenticationMethod != d.PasswordAndDevice || session.PasswordRevision != 1 || session.AccountRevision != 1 {
		t.Fatal(session, err)
	}
	if _, err = f.service.Complete(t.Context(), o.OperationID, initialPassword, sig, "127.0.0.1"); !errors.Is(err, d.ErrLoginCompleted) {
		t.Fatal("token disclosed twice", err)
	}
	second := f.beginPassword(t, public)
	reused, err := f.service.Complete(t.Context(), second.OperationID, initialPassword, signAuthentication(t, key, second.SigningPayload), "127.0.0.1")
	if err != nil || reused.CredentialID != result.CredentialID || reused.SessionToken == result.SessionToken {
		t.Fatal(reused, err)
	}
	// Losing the response does not require the password operation or its token.
	challenge, err := f.u.Begin(t.Context(), auth.Locator{Kind: auth.CredentialIDLocator, Value: []byte(result.CredentialID)}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := f.u.Complete(t.Context(), challenge.OperationID, signAuthentication(t, key, challenge.SigningPayload))
	if err != nil || recovered.AuthID != f.c.AuthID {
		t.Fatal(recovered, err)
	}
	for _, col := range []string{PasswordNotificationCollection, EmailQuotaCollection} {
		if n, _ := f.r.database.Collection(col).CountDocuments(t.Context(), bson.M{}); n != 0 {
			t.Fatal("login invoked mail", col, n)
		}
	}
}

type loginCountingEngine struct {
	p.RehashEngine
	calls *int
	after func()
}

func (e loginCountingEngine) Verify(ctx context.Context, secret string, m d.Material) (bool, error) {
	*e.calls++
	ok, err := e.RehashEngine.Verify(ctx, secret, m)
	if err == nil && e.after != nil {
		e.after()
	}
	return ok, err
}
func TestPasswordLoginDummyIsPermanentAndSameCost(t *testing.T) {
	f := newPasswordLoginFixture(t)
	key, public := passwordLoginKey(t)
	calls := 0
	s := f.newService(t, loginCountingEngine{RehashEngine: f.engine, calls: &calls})
	o, err := s.Begin(t.Context(), uuid.NewString(), "unknown@example.test", auth.ProtocolVersion, public, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Move the real role to this address after Begin. The captured placeholder
	// must never become a usable account even with the real password and proof.
	_, err = f.r.database.Collection(EmailBindingCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"email": "unknown@example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1"); !errors.Is(err, d.ErrAuthentication) || calls != 1 {
		t.Fatal("placeholder promoted or no verifier", calls, err)
	}
	stored, err := f.repo.read(t.Context(), bson.M{"operationId": o.OperationID})
	if err != nil || stored.Acceptable || stored.FailedAttempts != 1 {
		t.Fatal(stored, err)
	}
}
func TestPasswordLoginFiveSharedFailuresExpiryAndOwnerCapacity(t *testing.T) {
	t.Run("failures", func(t *testing.T) {
		f := newPasswordLoginFixture(t)
		key, public := passwordLoginKey(t)
		o := f.beginPassword(t, public)
		for i := 0; i < 5; i++ {
			secret := initialPassword
			payload := o.SigningPayload
			if i%2 == 0 {
				secret = "wrong password"
			} else {
				payload = []byte("wrong purpose")
			}
			if _, err := f.service.Complete(t.Context(), o.OperationID, secret, signAuthentication(t, key, payload), "127.0.0.1"); !errors.Is(err, d.ErrAuthentication) {
				t.Fatal(i, err)
			}
		}
		if _, err := f.service.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1"); !errors.Is(err, d.ErrAuthentication) {
			t.Fatal("sixth attempt", err)
		}
	})
	t.Run("expiry", func(t *testing.T) {
		f := newPasswordLoginFixture(t)
		key, public := passwordLoginKey(t)
		o := f.beginPassword(t, public)
		f.clock = o.ExpiresAt
		if _, err := f.service.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1"); !errors.Is(err, d.ErrAuthentication) {
			t.Fatal(err)
		}
	})
	for _, address := range []string{"primary@example.test", "unknown@example.test"} {
		t.Run(address, func(t *testing.T) {
			f := newPasswordLoginFixture(t)
			_, public := passwordLoginKey(t)
			for i := 0; i < 6; i++ {
				_, err := f.service.Begin(t.Context(), uuid.NewString(), address, auth.ProtocolVersion, public, "127.0.0.1")
				if (i == 5) != errors.Is(err, d.ErrLimited) {
					t.Fatal(i, err)
				}
			}
		})
	}
}
func TestPasswordLoginRejectsRetiredRevokedAndForeignKeys(t *testing.T) {
	for _, kind := range []string{"retired", "revoked", "foreign"} {
		t.Run(kind, func(t *testing.T) {
			f := newPasswordLoginFixture(t)
			if kind == "retired" {
				_, err := f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"accountRevision": int64(2), "minimumCredentialRevision": int64(2)}})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				set := bson.M{"revokedAt": f.clock}
				if kind == "foreign" {
					set = bson.M{"authId": "another-owner"}
				}
				if _, err := f.r.database.Collection(CredentialCollection).UpdateOne(t.Context(), bson.M{"credentialId": f.c.CredentialID}, bson.M{"$set": set}); err != nil {
					t.Fatal(err)
				}
			}
			o := f.beginPassword(t, f.c.PublicKey)
			if _, err := f.service.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, f.key, o.SigningPayload), "127.0.0.1"); !errors.Is(err, d.ErrAuthentication) {
				t.Fatal(kind, err)
			}
			var stored CredentialDocument
			_ = f.r.database.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": f.c.CredentialID}).Decode(&stored)
			if stored.CredentialRevision != 1 {
				t.Fatal("old key advanced", stored)
			}
		})
	}
}
func TestPasswordLoginFinalVersionsAndAuditRollback(t *testing.T) {
	for _, kind := range []string{"password", "role", "disable-restore", "closed", "audit"} {
		t.Run(kind, func(t *testing.T) {
			f := newPasswordLoginFixture(t)
			key, public := passwordLoginKey(t)
			o := f.beginPassword(t, public)
			calls := 0
			s := f.newService(t, loginCountingEngine{RehashEngine: f.engine, calls: &calls, after: func() {
				var err error
				switch kind {
				case "password":
					_, err = f.r.database.Collection(PasswordCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"passwordRevision": int64(1)}})
				case "role":
					_, err = f.r.database.Collection(EmailDirectoryCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"loginRoleRevision": int64(1)}})
				case "disable-restore":
					_, err = f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"accountRevision": int64(2)}})
				case "closed":
					_, err = f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"accountStatus": "CLOSED"}, "$inc": bson.M{"accountRevision": int64(1)}})
				case "audit":
					_, err = f.r.database.Collection(PasswordAuditCollection).InsertOne(t.Context(), bson.M{"operationId": o.OperationID, "authId": "fixture"})
				}
				if err != nil {
					t.Fatal(err)
				}
			}})
			if _, err := s.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1"); err == nil {
				t.Fatal("stale/failed audit claimed success")
			}
			if n, _ := f.r.database.Collection(CredentialCollection).CountDocuments(t.Context(), bson.M{}); n != 1 {
				t.Fatal("credential partially committed", n)
			}
			if n, _ := f.r.database.Collection(SessionCollection).CountDocuments(t.Context(), bson.M{}); n != 0 {
				t.Fatal("Session partially committed", n)
			}
		})
	}
}
func TestPasswordLoginConcurrentSamePublicKeyAndSingleOperation(t *testing.T) {
	for _, same := range []bool{false, true} {
		t.Run(map[bool]string{false: "different-operations", true: "same-operation"}[same], func(t *testing.T) {
			f := newPasswordLoginFixture(t)
			key, public := passwordLoginKey(t)
			ops := []auth.Challenge{f.beginPassword(t, public)}
			if same {
				ops = append(ops, ops[0])
			} else {
				ops = append(ops, f.beginPassword(t, public))
			}
			sigs := [][]byte{signAuthentication(t, key, ops[0].SigningPayload), signAuthentication(t, key, ops[1].SigningPayload)}
			results := make([]auth.Established, 2)
			errs := make([]error, 2)
			var wg sync.WaitGroup
			for i := range 2 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					results[i], errs[i] = f.service.Complete(t.Context(), ops[i].OperationID, initialPassword, sigs[i], "127.0.0.1")
				}()
			}
			wg.Wait()
			if same {
				success, completed := 0, 0
				for _, err := range errs {
					if err == nil {
						success++
					}
					if errors.Is(err, d.ErrLoginCompleted) {
						completed++
					}
				}
				if success != 1 || completed != 1 {
					t.Fatal(errs)
				}
			} else {
				if errs[0] != nil || errs[1] != nil || results[0].CredentialID != results[1].CredentialID {
					t.Fatal(results, errs)
				}
			}
			if n, _ := f.r.database.Collection(CredentialCollection).CountDocuments(t.Context(), bson.M{}); n != 2 {
				t.Fatal("duplicate registration", n)
			}
		})
	}
}
func TestPasswordLoginNFCAndRehashDoesNotChangeRevisions(t *testing.T) {
	f := newPasswordLoginFixture(t)
	secret := "a long café password value"
	material, err := f.engine.Hash(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.r.database.Collection(PasswordCollection).ReplaceOne(t.Context(), bson.M{"authId": f.c.AuthID}, passwordDoc(d.Record{AuthID: f.c.AuthID, Revision: 1, Material: material, ChangedAt: f.clock})); err != nil {
		t.Fatal(err)
	}
	stronger := passwordEngine(t, d.Parameters{MemoryKiB: 19456, Iterations: 3, Parallelism: 1})
	s := f.newService(t, stronger)
	key, public := passwordLoginKey(t)
	o := f.beginPassword(t, public)
	result, err := s.Complete(t.Context(), o.OperationID, "a long cafe\u0301 password value", signAuthentication(t, key, o.SigningPayload), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.repository.readPasswordTx(t.Context(), f.c.AuthID)
	if err != nil || record.Revision != 1 || record.Material.Parameters.Iterations != 3 || !record.ChangedAt.Equal(f.clock) {
		t.Fatal(record, err)
	}
	if session, err := f.u.Check(t.Context(), result.SessionToken); err != nil || session.AccountRevision != 1 {
		t.Fatal(session, err)
	}
}
func TestPasswordLoginUnknownCommitAndMalformedContext(t *testing.T) {
	t.Run("unknown-commit", func(t *testing.T) {
		f := newPasswordLoginFixture(t)
		key, public := passwordLoginKey(t)
		o := f.beginPassword(t, public)
		fault, appName := sessionRevocationFaultRepository(t, f.r.database)
		passwords, _ := NewPasswordRepository(fault, f.protocol.KeyID())
		repo, _ := NewPasswordLoginRepository(passwords, f.protocol)
		f.repo = repo
		calls := 0
		s := f.newService(t, loginCountingEngine{RehashEngine: f.engine, calls: &calls, after: func() {
			admin := f.r.database.Client().Database("admin")
			if err := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); err != nil {
				t.Fatal(err)
			}
		}})
		admin := f.r.database.Client().Database("admin")
		t.Cleanup(func() {
			_ = admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
		})
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		if result, err := s.Complete(ctx, o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1"); err == nil || result.SessionToken != "" {
			t.Fatal("unknown commit claimed success", err)
		}
		if calls != 1 {
			t.Fatal("final commit fault was not reached", calls)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		f := newPasswordLoginFixture(t)
		_, public := passwordLoginKey(t)
		o := f.beginPassword(t, public)
		_, err := f.r.database.Collection(PasswordLoginCollection).UpdateOne(t.Context(), bson.M{"operationId": o.OperationID}, bson.M{"$set": bson.M{"roleRevision": int32(1)}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.repo.ReadLogin(t.Context(), o.OperationID, f.clock); !errors.Is(err, d.ErrUnavailable) {
			t.Fatal(err)
		}
		_, _ = f.r.database.Collection(PasswordLoginCollection).UpdateOne(t.Context(), bson.M{"operationId": o.OperationID}, bson.M{"$set": bson.M{"roleRevision": int64(1)}})
		protocol, _ := passwordcrypto.NewProtocol(bytes32(11), "iwut-auth-center:other")
		repo, _ := NewPasswordLoginRepository(f.repository, protocol)
		if _, err = repo.ReadLogin(t.Context(), o.OperationID, f.clock); !errors.Is(err, d.ErrAuthentication) {
			t.Fatal(err)
		}
	})
}

func TestPasswordLoginNonLoginEmailAndResetRace(t *testing.T) {
	t.Run("non-login", func(t *testing.T) {
		f := newPasswordLoginFixture(t)
		key, public := passwordLoginKey(t)
		_, err := f.r.database.Collection(EmailBindingCollection).InsertOne(t.Context(), emailBindingDocument{BindingID: uuid.NewString(), AuthID: f.c.AuthID, Email: "extra@whut.edu.cn", VerifiedAt: f.clock})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.r.database.Collection(EmailDirectoryCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"verifiedCount": int64(2)}})
		if err != nil {
			t.Fatal(err)
		}
		o, err := f.service.Begin(t.Context(), uuid.NewString(), "extra@whut.edu.cn", auth.ProtocolVersion, public, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.service.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1"); !errors.Is(err, d.ErrAuthentication) {
			t.Fatal("non-login email accepted", err)
		}
	})
	t.Run("actual-reset-after-verification", func(t *testing.T) {
		f := newPasswordLoginFixture(t)
		key, public := passwordLoginKey(t)
		o := f.beginPassword(t, public)
		reset := buildResetFixture(t, f.passwordFixture)
		reset.clock = f.clock
		pending := reset.beginReset(t)
		calls := 0
		s := f.newService(t, loginCountingEngine{RehashEngine: f.engine, calls: &calls, after: func() {
			if err := reset.reset.Complete(t.Context(), pending.OperationID, reset.mail.code, changedPassword, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
		}})
		if _, err := s.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1"); !errors.Is(err, d.ErrAuthentication) {
			t.Fatal("old verification crossed reset", err)
		}
		if n, _ := f.r.database.Collection(CredentialCollection).CountDocuments(t.Context(), bson.M{}); n != 1 {
			t.Fatal("stale login registered key", n)
		}
	})
}
func TestPasswordLoginRetentionAndClosureCleanup(t *testing.T) {
	t.Run("retention", func(t *testing.T) {
		f := newPasswordLoginFixture(t)
		_, public := passwordLoginKey(t)
		o := f.beginPassword(t, public)
		f.clock = f.clock.Add(24 * time.Hour)
		if err := f.repository.PrunePasswordOperations(t.Context(), f.clock); err != nil {
			t.Fatal(err)
		}
		if n, _ := f.r.database.Collection(PasswordLoginCollection).CountDocuments(t.Context(), bson.M{"operationId": o.OperationID}); n != 0 {
			t.Fatal("login retained after deadline", n)
		}
	})
	t.Run("closure", func(t *testing.T) {
		f := newClosureFixture(t)
		closureInsert(t, f, PasswordLoginCollection, bson.M{"authId": f.c.AuthID, "operationId": uuid.NewString()})
		closureInsert(t, f, PasswordLoginCollection, bson.M{"authId": "other-owner", "operationId": uuid.NewString()})
		ready := f.ready(t)
		f.close(t, ready)
		f.acknowledge(t, ready.OperationID)
		f.drain(t)
		if closureCount(t, f, PasswordLoginCollection, bson.M{"authId": f.c.AuthID}) != 0 || closureCount(t, f, PasswordLoginCollection, bson.M{"authId": "other-owner"}) != 1 {
			t.Fatal("password login cleanup isolation failed")
		}
	})
}

func TestPasswordLoginSharesDeviceSessionLRU(t *testing.T) {
	f := newPasswordLoginFixture(t)
	sessions := make([]auth.Established, 10)
	for i := range sessions {
		sessions[i] = f.login(t)
		if _, err := f.r.database.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": sessions[i].SessionID}, bson.M{"$set": bson.M{"lastUsedAt": f.clock.Add(time.Duration(i+1) * time.Second)}}); err != nil {
			t.Fatal(err)
		}
	}
	f.clock = f.clock.Add(20 * time.Second)
	key, public := passwordLoginKey(t)
	o := f.beginPassword(t, public)
	first, err := f.service.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.u.Check(t.Context(), sessions[0].SessionToken); !errors.Is(err, ap.ErrSessionInvalid) {
		t.Fatal("password login did not evict device Session", err)
	}
	f.clock = f.clock.Add(time.Second)
	o = f.beginPassword(t, public)
	if _, err = f.service.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.r.database.Collection(SessionCollection).CountDocuments(t.Context(), bson.M{"revokedAt": nil}); n != 10 {
		t.Fatal("mixed-method LRU capacity", n)
	}
	if _, err = f.u.Check(t.Context(), first.SessionToken); err != nil {
		t.Fatal("password Session excluded from LRU", err)
	}
	if n, _ := f.r.database.Collection(CredentialCollection).CountDocuments(t.Context(), bson.M{"revokedAt": nil}); n != 2 {
		t.Fatal("LRU revoked credential", n)
	}
}

func TestPasswordLoginAddressBudgetSurvivesChallengeAndOperationKeyRotation(t *testing.T) {
	f := newPasswordLoginFixture(t)
	key, public := passwordLoginKey(t)
	for batch := 0; batch < 2; batch++ {
		o, err := f.service.Begin(t.Context(), uuid.NewString(), "unknown@example.test", auth.ProtocolVersion, public, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		sig := signAuthentication(t, key, o.SigningPayload)
		for range 5 {
			if _, err = f.service.Complete(t.Context(), o.OperationID, initialPassword, sig, "127.0.0.1"); !errors.Is(err, d.ErrAuthentication) {
				t.Fatal(err)
			}
		}
	}
	protocol, _ := passwordcrypto.NewProtocol(bytes32(21), "iwut-auth-center:test")
	passwords, _ := NewPasswordRepository(f.r, protocol.KeyID())
	repo, _ := NewPasswordLoginRepository(passwords, protocol)
	f.repo = repo
	f.protocol = protocol
	service := f.newService(t, f.engine)
	o, err := service.Begin(t.Context(), uuid.NewString(), "unknown@example.test", auth.ProtocolVersion, public, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1"); !errors.Is(err, d.ErrLimited) {
		t.Fatal("new challenge/key replenished work budget", err)
	}
	stored, err := repo.read(t.Context(), bson.M{"operationId": o.OperationID})
	if err != nil || stored.FailedAttempts != 0 {
		t.Fatal("quota rejection consumed proof failure", stored, err)
	}
}
func TestPasswordLoginDamagedVerifierIsDependencyFailure(t *testing.T) {
	f := newPasswordLoginFixture(t)
	key, public := passwordLoginKey(t)
	o := f.beginPassword(t, public)
	if _, err := f.r.database.Collection(PasswordCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"hash": []byte{1}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Complete(t.Context(), o.OperationID, initialPassword, signAuthentication(t, key, o.SigningPayload), "127.0.0.1"); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("damaged verifier disguised as bad password", err)
	}
	stored, err := f.repo.read(t.Context(), bson.M{"operationId": o.OperationID})
	if err != nil || stored.FailedAttempts != 0 {
		t.Fatal(stored, err)
	}
}
