package mongo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/associationcrypto"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/registration/domain"
	"iwut-auth-center/internal/registration/port"
	"iwut-auth-center/internal/registration/usecase"
)

type registrationFixture struct {
	db       *drivermongo.Database
	repo     *RegistrationRepository
	crypto   *associationcrypto.Crypto
	protocol *deviceprotocol.Protocol
	uc       *usecase.Registration
}

func newRegistrationFixture(t *testing.T) *registrationFixture {
	t.Helper()
	uri := os.Getenv("MONGODB_INTEGRATION_URI")
	if uri == "" {
		t.Skip("MONGODB_INTEGRATION_URI is required")
	}
	client, err := drivermongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	db := client.Database("uc006_" + uuid.NewString())
	ctx := context.Background()
	var hello bson.M
	if err = db.RunCommand(ctx, bson.M{"hello": 1}).Decode(&hello); err != nil {
		t.Fatal(err)
	}
	if _, ok := hello["setName"]; !ok {
		t.Skip("registration transactions require replica set")
	}
	t.Cleanup(func() { _ = db.Drop(context.Background()); _ = client.Disconnect(context.Background()) })
	for _, ensure := range []func(context.Context, *drivermongo.Database) error{EnsurePrincipalSchema, EnsureAuthenticationSchema, EnsureAssociationSchema} {
		if err := ensure(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	authRepo, err := NewAuthenticationRepository(db, 10000, 5)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewRegistrationRepository(db, authRepo)
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := associationcrypto.New(associationcrypto.Key{Version: "v1", Encrypt: bytes.Repeat([]byte{1}, 32), Lookup: bytes.Repeat([]byte{2}, 32)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	protocol, _ := deviceprotocol.New("iwut-auth-center:test")
	limits := deviceprotocol.RateLimits{BeginGlobal: 100000, CompleteGlobal: 100000, BeginSource: 100000, CompleteLocator: 100000, MaxBuckets: 4096}
	limiter, _ := deviceprotocol.NewLimiter(limits)
	u, err := usecase.NewRegistration(repo, protocol, crypto, limiter, "iwut-auth-center:test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &registrationFixture{db, repo, crypto, protocol, u}
}
func newSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func signChallenge(t *testing.T, key *ecdsa.PrivateKey, c auth.Challenge) []byte {
	t.Helper()
	h := sha256.Sum256(c.SigningPayload)
	s, e := ecdsa.SignASN1(rand.Reader, key, h[:])
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func beginRegistration(t *testing.T, f *registrationFixture, key *ecdsa.PrivateKey, token []byte) auth.Challenge {
	t.Helper()
	c, e := f.uc.Begin(context.Background(), auth.ProtocolVersion, elliptic.Marshal(elliptic.P256(), key.X, key.Y), domain.AssociationScheme, token, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func countDocuments(t *testing.T, db *drivermongo.Database, c string, filter bson.M) int64 {
	t.Helper()
	n, e := db.Collection(c).CountDocuments(context.Background(), filter)
	if e != nil {
		t.Fatal(e)
	}
	return n
}

func TestRegistrationRealMongoAtomicityPrivacyAndDuplicateRecovery(t *testing.T) {
	f := newRegistrationFixture(t)
	ctx := context.Background()
	key := newSigningKey(t)
	token := bytes.Repeat([]byte{9}, 32)
	c := beginRegistration(t, f, key, token)
	var pending bson.Raw
	if err := f.db.Collection(AuthenticationOperationCollection).FindOne(ctx, bson.M{"operationId": c.OperationID}).Decode(&pending); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(pending, token) || pending.Lookup("signingPayload").Type != 0 || pending.Lookup("associationDigest").Type != 0 {
		t.Fatal("plaintext persisted")
	}
	result, err := f.uc.Complete(ctx, c.OperationID, signChallenge(t, key, c))
	if err != nil {
		t.Fatal(err)
	}
	var principal bson.Raw
	if err = f.db.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": result.AuthID}).Decode(&principal); err != nil {
		t.Fatal(err)
	}
	if principal.Lookup("principalType").StringValue() != "USER" || principal.Lookup("accountStatus").StringValue() != "ACTIVE" || principal.Lookup("permissionRevision").Int64() != 1 || principal.Lookup("developerStatus").Type != bson.TypeNull {
		t.Fatal("wrong initial principal")
	}
	profile := principal.Lookup("profile").Document()
	entries, e := profile.Lookup("entries").Array().Values()
	if e != nil || len(entries) != 0 || profile.Lookup("revision").Int64() != 1 || profile.Lookup("updatedAt").DateTime() != principal.Lookup("createdAt").DateTime() {
		t.Fatal("invalid empty profile")
	}
	op, err := f.repo.GetOperation(ctx, c.OperationID)
	if err != nil || op.Status != auth.Completed || len(op.Ciphertext) != 0 || len(op.LookupKey) != 0 {
		t.Fatal("operation was not consumed and scrubbed")
	}
	digest, _ := f.protocol.TokenDigest(result.SessionToken)
	if _, err = f.repo.CheckSession(ctx, digest, time.Now()); err != nil {
		t.Fatal("initial session invalid", err)
	}
	if _, err = f.uc.Complete(ctx, c.OperationID, signChallenge(t, key, c)); !errors.Is(err, port.ErrAlreadyCompleted) {
		t.Fatal("replayed operation", err)
	}
	duplicate := beginRegistration(t, f, key, token)
	if _, err = f.uc.Complete(ctx, duplicate.OperationID, signChallenge(t, key, duplicate)); !errors.Is(err, port.ErrCredentialRegistered) {
		t.Fatal("duplicate key", err)
	}
	if countDocuments(t, f.db, PrincipalCollection, bson.M{}) != 1 || countDocuments(t, f.db, SessionCollection, bson.M{}) != 1 || countDocuments(t, f.db, AssociationMemberCollection, bson.M{}) != 1 {
		t.Fatal("duplicate created account")
	}
	fingerprint, _ := f.protocol.Fingerprint(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
	credential, acceptable, err := f.repo.ResolveCredential(ctx, auth.Locator{Kind: auth.FingerprintLocator, Value: fingerprint})
	if err != nil || !acceptable || credential.AuthID != result.AuthID {
		t.Fatal("lost-response key could not recover original account")
	}
	var session bson.Raw
	_ = f.db.Collection(SessionCollection).FindOne(ctx, bson.M{"sessionId": result.SessionID}).Decode(&session)
	if bytes.Contains(session, []byte(result.SessionToken)) || session.Lookup("sessionToken").Type != 0 {
		t.Fatal("session secret persisted")
	}
}

func TestRegistrationConcurrentSameOperationAndSameAssociation(t *testing.T) {
	f := newRegistrationFixture(t)
	ctx := context.Background()
	token := bytes.Repeat([]byte{8}, 32)
	key := newSigningKey(t)
	c := beginRegistration(t, f, key, token)
	sig := signChallenge(t, key, c)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := f.uc.Complete(ctx, c.OperationID, sig); errs <- err }()
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, port.ErrAlreadyCompleted) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("multiple consumers", success)
	}
	errCh := make(chan error, 6)
	for i := 0; i < 6; i++ {
		k := newSigningKey(t)
		ch := beginRegistration(t, f, k, token)
		signature := signChallenge(t, k, ch)
		wg.Add(1)
		go func() { defer wg.Done(); _, e := f.uc.Complete(ctx, ch.OperationID, signature); errCh <- e }()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if countDocuments(t, f.db, AssociationCollection, bson.M{}) != 1 || countDocuments(t, f.db, AssociationMemberCollection, bson.M{}) != 7 || countDocuments(t, f.db, PrincipalCollection, bson.M{}) != 7 {
		t.Fatal("association incorrectly merged accounts or duplicated groups")
	}
}

func TestRegistrationRollbackAtEveryDocumentStage(t *testing.T) {
	for _, collection := range []string{AuthenticationOperationCollection, PrincipalCollection, CredentialCollection, AssociationCollection, AssociationMemberCollection, SessionCollection} {
		t.Run(collection, func(t *testing.T) {
			f := newRegistrationFixture(t)
			ctx := context.Background()
			key := newSigningKey(t)
			c := beginRegistration(t, f, key, bytes.Repeat([]byte{7}, 32))
			sig := signChallenge(t, key, c)
			// A real server-side validator rejects this write after preceding writes
			// have occurred inside the same transaction.
			err := f.db.RunCommand(ctx, bson.D{{Key: "collMod", Value: collection}, {Key: "validator", Value: bson.M{"impossibleTestField": bson.M{"$exists": true}}}, {Key: "validationLevel", Value: "strict"}}).Err()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.uc.Complete(ctx, c.OperationID, sig); !errors.Is(err, port.ErrUnavailable) {
				t.Fatal("expected unavailable", err)
			}
			for _, name := range []string{PrincipalCollection, CredentialCollection, AssociationCollection, AssociationMemberCollection, SessionCollection} {
				if countDocuments(t, f.db, name, bson.M{}) != 0 {
					t.Fatal("partial commit", name)
				}
			}
			op, _ := f.repo.GetOperation(ctx, c.OperationID)
			if op.Status != auth.Pending || len(op.Ciphertext) != 48 {
				t.Fatal("challenge consumed on rollback")
			}
			if err = f.db.RunCommand(ctx, bson.D{{Key: "collMod", Value: collection}, {Key: "validator", Value: bson.M{}}}).Err(); err != nil {
				t.Fatal(err)
			}
			if _, err = f.uc.Complete(ctx, c.OperationID, sig); err != nil {
				t.Fatal("same proof cannot retry rolled-back registration", err)
			}
		})
	}
}

func TestRegistrationInvalidProofAndExpirationCloseEncryptedSnapshot(t *testing.T) {
	f := newRegistrationFixture(t)
	ctx := context.Background()
	key := newSigningKey(t)
	c := beginRegistration(t, f, key, bytes.Repeat([]byte{4}, 32))
	for i := 0; i < 5; i++ {
		if _, err := f.uc.Complete(ctx, c.OperationID, []byte{1}); !errors.Is(err, port.ErrProofInvalid) {
			t.Fatal(err)
		}
	}
	op, _ := f.repo.GetOperation(ctx, c.OperationID)
	if op.Status != auth.Closed || len(op.Ciphertext) != 0 {
		t.Fatal("exhausted proof retained token")
	}
	if _, err := f.uc.Complete(ctx, c.OperationID, signChallenge(t, key, c)); !errors.Is(err, port.ErrProofInvalid) {
		t.Fatal("closed proof accepted")
	}
	expired := beginRegistration(t, f, key, bytes.Repeat([]byte{4}, 32))
	_, err := f.db.Collection(AuthenticationOperationCollection).UpdateOne(ctx, bson.M{"operationId": expired.OperationID}, bson.M{"$set": bson.M{"expiresAt": time.Now().Add(-time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.uc.Complete(ctx, expired.OperationID, signChallenge(t, key, expired)); !errors.Is(err, port.ErrProofInvalid) {
		t.Fatal("expired proof", err)
	}
	op, _ = f.repo.GetOperation(ctx, expired.OperationID)
	if op.Status != auth.Closed || len(op.Ciphertext) != 0 {
		t.Fatal("expired snapshot retained")
	}
	if countDocuments(t, f.db, PrincipalCollection, bson.M{}) != 0 {
		t.Fatal("invalid proof created account")
	}
}
