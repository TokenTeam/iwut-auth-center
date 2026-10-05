package mongo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/authentication/usecase"
)

type authenticationFixture struct {
	r   *AuthenticationRepository
	p   *deviceprotocol.Protocol
	u   *usecase.Login
	key *ecdsa.PrivateKey
	c   domain.Credential
}

func newAuthenticationFixture(t *testing.T) authenticationFixture {
	t.Helper()
	db := integrationDatabase(t)
	if err := EnsurePrincipalSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureAuthenticationSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	r, err := NewAuthenticationRepository(db, 10000, 5)
	if err != nil {
		t.Fatal(err)
	}
	p, err := deviceprotocol.New("iwut-auth-center:test")
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 100000, CompleteGlobal: 100000, BeginSource: 100000, CompleteLocator: 100000, MaxBuckets: 10000})
	if err != nil {
		t.Fatal(err)
	}
	u, err := usecase.NewLogin(r, p, limiter, "iwut-auth-center:test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(key.Curve, key.X, key.Y)
	fingerprint, err := p.Fingerprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.NewID()
	if err != nil {
		t.Fatal(err)
	}
	credential := domain.Credential{CredentialID: id, AuthID: "user-login", ProtocolVersion: domain.ProtocolVersion, PublicKey: publicKey, Fingerprint: fingerprint, CreatedAt: time.Now().UTC().Truncate(time.Millisecond)}
	if _, err := db.Collection(PrincipalCollection).InsertOne(t.Context(), bson.M{"authId": credential.AuthID, "principalType": "USER", "accountStatus": "ACTIVE", "accountRevision": int64(1)}); err != nil {
		t.Fatal(err)
	}
	if err := r.WithAuthTransaction(t.Context(), func(ctx context.Context) error { return r.InsertCredentialTx(ctx, credential) }); err != nil {
		t.Fatal(err)
	}
	return authenticationFixture{r, p, u, key, credential}
}

func (f authenticationFixture) begin(t *testing.T) domain.Challenge {
	t.Helper()
	challenge, err := f.u.Begin(t.Context(), domain.Locator{Kind: domain.CredentialIDLocator, Value: []byte(f.c.CredentialID)}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return challenge
}
func signAuthentication(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signature
}
func (f authenticationFixture) login(t *testing.T) domain.Established {
	t.Helper()
	challenge := f.begin(t)
	session, err := f.u.Complete(t.Context(), challenge.OperationID, signAuthentication(t, f.key, challenge.SigningPayload))
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestAuthenticationLoginProofReplayAndSessionStorage(t *testing.T) {
	f := newAuthenticationFixture(t)
	challenge := f.begin(t)
	signature := signAuthentication(t, f.key, challenge.SigningPayload)
	session, err := f.u.Complete(t.Context(), challenge.OperationID, signature)
	if err != nil {
		t.Fatal(err)
	}
	if session.AuthID != f.c.AuthID || session.CredentialID != f.c.CredentialID {
		t.Fatal("wrong owner")
	}
	if _, err := f.u.Complete(t.Context(), challenge.OperationID, signature); !errors.Is(err, port.ErrAlreadyCompleted) {
		t.Fatal("replay", err)
	}
	checked, err := f.u.Check(t.Context(), session.SessionToken)
	if err != nil || checked.SessionID != session.SessionID || !checked.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatal("check", err)
	}
	var stored bson.M
	if err := f.r.database.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": session.SessionID}).Decode(&stored); err != nil {
		t.Fatal(err)
	}
	encoded, err := bson.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(session.SessionToken)) || stored["sessionToken"] != nil {
		t.Fatal("plaintext session token persisted")
	}
	if _, err := f.u.Check(t.Context(), session.SessionID); !errors.Is(err, port.ErrSessionInvalid) {
		t.Fatal("sessionId authenticated", err)
	}
	if _, err := f.u.Complete(t.Context(), "unknown", signature); !errors.Is(err, port.ErrAuthenticationFailed) {
		t.Fatal("unknown operation", err)
	}
}

func TestAuthenticationProofContextAndAttemptClosure(t *testing.T) {
	f := newAuthenticationFixture(t)
	for _, index := range []int{2, 3, 5, 9} {
		challenge := f.begin(t)
		fields, err := deviceprotocol.ParseFrame(challenge.SigningPayload, 11)
		if err != nil {
			t.Fatal(err)
		}
		fields[index][0] ^= 1
		if _, err := f.u.Complete(t.Context(), challenge.OperationID, signAuthentication(t, f.key, deviceprotocol.Frame(fields...))); !errors.Is(err, port.ErrAuthenticationFailed) {
			t.Fatalf("context index %d: %v", index, err)
		}
	}
	challenge := f.begin(t)
	for range 5 {
		if _, err := f.u.Complete(t.Context(), challenge.OperationID, []byte("bad")); !errors.Is(err, port.ErrAuthenticationFailed) {
			t.Fatal(err)
		}
	}
	op, err := f.r.GetOperation(t.Context(), challenge.OperationID)
	if err != nil || op.Status != domain.Closed || op.FailedAttempts != 5 {
		t.Fatal("failure state", op.Status, op.FailedAttempts, err)
	}
	if _, err := f.u.Complete(t.Context(), challenge.OperationID, signAuthentication(t, f.key, challenge.SigningPayload)); !errors.Is(err, port.ErrAuthenticationFailed) {
		t.Fatal("closed challenge accepted", err)
	}
}

func TestAuthenticationUnknownBeginRemainsUnacceptableAndExpiry(t *testing.T) {
	f := newAuthenticationFixture(t)
	if _, err := f.r.database.Collection(CredentialCollection).DeleteOne(t.Context(), bson.M{"credentialId": f.c.CredentialID}); err != nil {
		t.Fatal(err)
	}
	challenge := f.begin(t)
	if err := f.r.WithAuthTransaction(t.Context(), func(ctx context.Context) error { return f.r.InsertCredentialTx(ctx, f.c) }); err != nil {
		t.Fatal(err)
	}
	if _, err := f.u.Complete(t.Context(), challenge.OperationID, signAuthentication(t, f.key, challenge.SigningPayload)); !errors.Is(err, port.ErrAuthenticationFailed) {
		t.Fatal("formerly unknown credential accepted", err)
	}
	challenge = f.begin(t)
	future := challenge.ExpiresAt.Add(time.Millisecond)
	f.r.clock = func() time.Time { return future }
	if _, err := f.u.Complete(t.Context(), challenge.OperationID, signAuthentication(t, f.key, challenge.SigningPayload)); !errors.Is(err, port.ErrAuthenticationFailed) {
		t.Fatal("transaction used stale challenge time", err)
	}
}

func TestAuthenticationConcurrentConsumptionAndCapacity(t *testing.T) {
	f := newAuthenticationFixture(t)
	challenge := f.begin(t)
	signature := signAuthentication(t, f.key, challenge.SigningPayload)
	var group sync.WaitGroup
	results := make(chan error, 12)
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := f.u.Complete(t.Context(), challenge.OperationID, signature)
			results <- err
		}()
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, port.ErrAlreadyCompleted) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("duplicate consumption", success)
	}
	challenges := make([]domain.Challenge, 14)
	signatures := make([][]byte, 14)
	for i := range challenges {
		challenges[i] = f.begin(t)
		signatures[i] = signAuthentication(t, f.key, challenges[i].SigningPayload)
	}
	results = make(chan error, len(challenges))
	for i := range challenges {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			_, err := f.u.Complete(t.Context(), challenges[i].OperationID, signatures[i])
			results <- err
		}(i)
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	count, err := f.r.database.Collection(SessionCollection).CountDocuments(t.Context(), bson.M{"authId": f.c.AuthID, "revokedAt": nil, "expiresAt": bson.M{"$gt": time.Now()}})
	if err != nil || count != 10 {
		t.Fatal("concurrent capacity", count, err)
	}
}

func TestAuthenticationExactLRUAndFailedCommitRollback(t *testing.T) {
	f := newAuthenticationFixture(t)
	sessions := make([]domain.Established, 10)
	for i := range sessions {
		sessions[i] = f.login(t)
	}
	future := time.Now().Add(time.Minute)
	f.r.clock = func() time.Time { return future }
	used, err := f.u.Check(t.Context(), sessions[0].SessionToken)
	if err != nil || !used.LastUsedAt.Equal(future.UTC().Truncate(time.Millisecond)) {
		t.Fatal("synchronous use update", err)
	}
	newSession := f.login(t)
	if _, err := f.u.Check(t.Context(), sessions[1].SessionToken); !errors.Is(err, port.ErrSessionInvalid) {
		t.Fatal("LRU did not evict least recently used", err)
	}
	if _, err := f.u.Check(t.Context(), sessions[0].SessionToken); err != nil {
		t.Fatal("recently used oldest session evicted", err)
	}
	if _, err := f.u.Check(t.Context(), newSession.SessionToken); err != nil {
		t.Fatal("new session evicted", err)
	}
	challenge := f.begin(t)
	op, err := f.r.GetOperation(t.Context(), challenge.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := f.p.TokenDigest(newSession.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.p.NewID()
	if err != nil {
		t.Fatal(err)
	}
	bad := domain.Session{AccountRevision: 1, SessionID: id, AuthID: f.c.AuthID, CredentialID: f.c.CredentialID, TokenDigest: digest, AuthenticationMethod: "DEVICE_CREDENTIAL", AuthenticatedAt: future, CreatedAt: future, LastUsedAt: future, ExpiresAt: future.Add(time.Hour)}
	if err := f.r.CompleteLogin(t.Context(), op, bad, future); !errors.Is(err, port.ErrUnavailable) {
		t.Fatal("injected duplicate digest should abort", err)
	}
	op, err = f.r.GetOperation(t.Context(), challenge.OperationID)
	if err != nil || op.Status != domain.Pending {
		t.Fatal("failed transaction consumed challenge", err)
	}
	count, err := f.r.database.Collection(SessionCollection).CountDocuments(t.Context(), bson.M{"revokedAt": nil})
	if err != nil || count != 10 {
		t.Fatal("failed transaction evicted old session", count, err)
	}
}

func TestAuthenticationSessionCurrentStateAndCorruptionFailClosed(t *testing.T) {
	for _, change := range []string{"disabled", "system", "revoked", "corrupt-key", "corrupt-fingerprint", "expired"} {
		t.Run(change, func(t *testing.T) {
			f := newAuthenticationFixture(t)
			session := f.login(t)
			switch change {
			case "disabled":
				_, err := f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"accountStatus": "DISABLED"}})
				if err != nil {
					t.Fatal(err)
				}
			case "system":
				_, err := f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"principalType": "SYSTEM"}})
				if err != nil {
					t.Fatal(err)
				}
			case "revoked":
				_, err := f.r.database.Collection(CredentialCollection).UpdateOne(t.Context(), bson.M{"credentialId": f.c.CredentialID}, bson.M{"$set": bson.M{"revokedAt": time.Now()}})
				if err != nil {
					t.Fatal(err)
				}
			case "corrupt-key":
				_, err := f.r.database.Collection(CredentialCollection).UpdateOne(t.Context(), bson.M{"credentialId": f.c.CredentialID}, bson.M{"$set": bson.M{"publicKey": append([]byte{4}, make([]byte, 64)...)}})
				if err != nil {
					t.Fatal(err)
				}
			case "corrupt-fingerprint":
				_, err := f.r.database.Collection(CredentialCollection).UpdateOne(t.Context(), bson.M{"credentialId": f.c.CredentialID}, bson.M{"$set": bson.M{"fingerprint": make([]byte, 32)}})
				if err != nil {
					t.Fatal(err)
				}
			case "expired":
				f.r.clock = func() time.Time { return session.ExpiresAt }
			}
			if _, err := f.u.Check(t.Context(), session.SessionToken); !errors.Is(err, port.ErrSessionInvalid) {
				t.Fatal("bad current state accepted", err)
			}
		})
	}
}

func TestAuthenticationRevocationAndDisableSerializeWithLogin(t *testing.T) {
	for _, change := range []string{"principal", "credential"} {
		t.Run(change, func(t *testing.T) {
			f := newAuthenticationFixture(t)
			challenge := f.begin(t)
			signature := signAuthentication(t, f.key, challenge.SigningPayload)
			locked := make(chan struct{})
			release := make(chan struct{})
			revocation := make(chan error, 1)
			go func() {
				revocation <- f.r.WithAuthTransaction(t.Context(), func(ctx context.Context) error {
					if change == "principal" {
						if _, err := f.r.database.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"accountStatus": "DISABLED"}}); err != nil {
							return err
						}
					} else {
						if _, err := f.r.database.Collection(CredentialCollection).UpdateOne(ctx, bson.M{"credentialId": f.c.CredentialID}, bson.M{"$set": bson.M{"revokedAt": time.Now()}}); err != nil {
							return err
						}
					}
					close(locked)
					<-release
					return nil
				})
			}()
			<-locked
			login := make(chan error, 1)
			go func() { _, err := f.u.Complete(t.Context(), challenge.OperationID, signature); login <- err }()
			close(release)
			if err := <-revocation; err != nil {
				t.Fatal(err)
			}
			if err := <-login; !errors.Is(err, port.ErrAuthenticationFailed) {
				t.Fatal("login survived earlier revocation", err)
			}
		})
	}
}

func TestAuthenticationPendingCapacityAtomicAndExpiredCipherCleanup(t *testing.T) {
	f := newAuthenticationFixture(t)
	f.r.maxPending = 1
	first := f.begin(t)
	if _, err := f.u.Begin(t.Context(), domain.Locator{Kind: domain.CredentialIDLocator, Value: []byte(f.c.CredentialID)}, "other"); !errors.Is(err, port.ErrLimitExceeded) {
		t.Fatal("pending capacity", err)
	}
	if _, err := f.r.database.Collection(AuthenticationOperationCollection).UpdateOne(t.Context(), bson.M{"operationId": first.OperationID}, bson.M{"$set": bson.M{"expiresAt": time.Now().Add(-time.Minute), "purpose": domain.Register, "nonce": []byte("nonce"), "ciphertext": []byte("secret"), "lookupKey": []byte("lookup")}}); err != nil {
		t.Fatal(err)
	}
	f.begin(t)
	op, err := f.r.GetOperation(t.Context(), first.OperationID)
	if err != nil || op.Status != domain.Closed || len(op.Ciphertext) != 0 || len(op.Nonce) != 0 || len(op.LookupKey) != 0 {
		t.Fatal("expired operation not cleaned", err)
	}
}

func TestAuthenticationHistoricalCapacityAndStableTieOrder(t *testing.T) {
	f := newAuthenticationFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	for i := 0; i < 12; i++ {
		_, digest, err := f.p.NewSessionToken()
		if err != nil {
			t.Fatal(err)
		}
		session := domain.Session{AccountRevision: 1, SessionID: fmt.Sprintf("11111111-1111-4111-8111-%012d", i), AuthID: f.c.AuthID, CredentialID: f.c.CredentialID, TokenDigest: digest, AuthenticationMethod: "DEVICE_CREDENTIAL", CreatedAt: now, AuthenticatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}
		if _, err := f.r.database.Collection(SessionCollection).InsertOne(t.Context(), sessionDocument(session)); err != nil {
			t.Fatal(err)
		}
	}
	f.login(t)
	count, err := f.r.database.Collection(SessionCollection).CountDocuments(t.Context(), bson.M{"revokedAt": nil})
	if err != nil || count != 10 {
		t.Fatal("legacy capacity not converged", count, err)
	}
	for i := 0; i < 12; i++ {
		var doc SessionDocument
		if err := f.r.database.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": fmt.Sprintf("11111111-1111-4111-8111-%012d", i)}).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if (doc.RevokedAt != nil) != (i < 3) {
			t.Fatal("stable tie order mismatch", i)
		}
	}
}

func TestAuthenticationConcurrentPendingCapacityAndFailures(t *testing.T) {
	f := newAuthenticationFixture(t)
	f.r.maxPending = 3
	var group sync.WaitGroup
	results := make(chan error, 12)
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := f.u.Begin(t.Context(), domain.Locator{Kind: domain.FingerprintLocator, Value: f.c.Fingerprint}, "127.0.0.1")
			results <- err
		}()
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, port.ErrLimitExceeded) {
			t.Fatal(err)
		}
	}
	if success != 3 {
		t.Fatal("concurrent pending capacity", success)
	}
	var op OperationDocument
	if err := f.r.database.Collection(AuthenticationOperationCollection).FindOne(t.Context(), bson.M{}).Decode(&op); err != nil {
		t.Fatal(err)
	}
	results = make(chan error, 12)
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := f.u.Complete(t.Context(), op.OperationID, []byte("bad"))
			results <- err
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, port.ErrAuthenticationFailed) {
			t.Fatal(err)
		}
	}
	stored, err := f.r.GetOperation(t.Context(), op.OperationID)
	if err != nil || stored.FailedAttempts != 5 || stored.Status != domain.Closed {
		t.Fatal("unbounded concurrent attempts", stored.FailedAttempts, err)
	}
}
