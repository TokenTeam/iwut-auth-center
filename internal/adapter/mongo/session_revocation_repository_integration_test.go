package mongo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
)

func sessionRevocationFixture(t *testing.T) (*AuthenticationRepository, *drivermongo.Database, SessionDocument, SessionDocument) {
	t.Helper()
	db := integrationDatabase(t)
	if err := EnsureAuthenticationSchema(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	repo, _ := NewAuthenticationRepository(db, 100, 5)
	protocol, _ := deviceprotocol.New("test")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	public := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	fingerprint, _ := protocol.Fingerprint(public)
	credentialID, _ := protocol.NewID()
	now := time.Now().UTC().Truncate(time.Millisecond)
	credential := CredentialDocument{CredentialID: credentialID, AuthID: "session-revocation-user", ProtocolVersion: domain.ProtocolVersion, PublicKey: public, Fingerprint: fingerprint, CreatedAt: now}
	if _, err := db.Collection(CredentialCollection).InsertOne(t.Context(), credential); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection(PrincipalCollection).InsertOne(t.Context(), bson.M{"authId": credential.AuthID, "principalType": "USER", "accountStatus": "ACTIVE", "profile": bson.M{"name": "keep"}}); err != nil {
		t.Fatal(err)
	}
	sessions := make([]SessionDocument, 2)
	for i := range sessions {
		id, _ := protocol.NewID()
		_, digest, _ := protocol.NewSessionToken()
		sessions[i] = SessionDocument{SessionID: id, AuthID: credential.AuthID, AuthenticationMethod: "DEVICE_CREDENTIAL", CredentialID: credentialID, TokenDigest: digest, AuthenticatedAt: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}
		if _, err := db.Collection(SessionCollection).InsertOne(t.Context(), sessions[i]); err != nil {
			t.Fatal(err)
		}
	}
	return repo, db, sessions[0], sessions[1]
}

func TestSessionRevocationMongoConcurrentIdempotencyAndIsolation(t *testing.T) {
	repo, db, current, other := sessionRevocationFixture(t)
	if _, err := repo.CheckSession(t.Context(), current.TokenDigest, time.Now()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errorsByCall := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errorsByCall <- repo.RevokeCurrentSession(t.Context(), current.TokenDigest, time.Now())
		}()
	}
	wg.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatal(err)
		}
	}
	var revoked SessionDocument
	if err := db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": current.SessionID}).Decode(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked.RevokedAt == nil {
		t.Fatal("no revokedAt")
	}
	first := *revoked.RevokedAt
	if err := repo.RevokeCurrentSession(t.Context(), current.TokenDigest, first.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": current.SessionID}).Decode(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked.RevokedAt.Equal(first) {
		t.Fatal("retry changed first revocation time")
	}
	if _, err := repo.CheckSession(t.Context(), current.TokenDigest, time.Now()); !errors.Is(err, port.ErrSessionInvalid) {
		t.Fatalf("revoked check=%v", err)
	}
	if _, err := repo.CheckSession(t.Context(), other.TokenDigest, time.Now()); err != nil {
		t.Fatalf("other session changed: %v", err)
	}
	var credential CredentialDocument
	if err := db.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": current.CredentialID}).Decode(&credential); err != nil || credential.RevokedAt != nil {
		t.Fatalf("credential changed: %v", err)
	}
	count, err := db.Collection(PrincipalCollection).CountDocuments(t.Context(), bson.M{"authId": current.AuthID, "profile.name": "keep", "accountStatus": "ACTIVE"})
	if err != nil || count != 1 {
		t.Fatalf("principal/profile changed: count=%d err=%v", count, err)
	}
}

func TestSessionRevocationMongoExpiredUnknownAndDisabledOwner(t *testing.T) {
	repo, db, current, _ := sessionRevocationFixture(t)
	_, err := db.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": current.SessionID}, bson.M{"$set": bson.M{"expiresAt": time.Now().Add(-time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": current.AuthID}, bson.M{"$set": bson.M{"accountStatus": "DISABLED"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RevokeCurrentSession(t.Context(), current.TokenDigest, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := repo.RevokeCurrentSession(t.Context(), make([]byte, 32), time.Now()); err != nil {
		t.Fatal(err)
	}
	var revoked SessionDocument
	if err := db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": current.SessionID}).Decode(&revoked); err != nil || revoked.RevokedAt == nil {
		t.Fatalf("expired not revoked: %v", err)
	}
}

func TestSessionRevocationMongoCheckCommitOrder(t *testing.T) {
	repo, _, current, _ := sessionRevocationFixture(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.CheckSession(t.Context(), current.TokenDigest, time.Now())
			if err != nil && !errors.Is(err, port.ErrSessionInvalid) {
				t.Errorf("concurrent check: %v", err)
			}
		}()
	}
	if err := repo.RevokeCurrentSession(t.Context(), current.TokenDigest, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Checks initiated after confirmed revocation must always observe it.
	for range 8 {
		if _, err := repo.CheckSession(t.Context(), current.TokenDigest, time.Now()); !errors.Is(err, port.ErrSessionInvalid) {
			t.Fatalf("post-commit check: %v", err)
		}
	}
	wg.Wait()
}

func TestSessionRevocationMongoFailureAndRetry(t *testing.T) {
	_, db, current, _ := sessionRevocationFixture(t)
	repo, appName := sessionRevocationFaultRepository(t, db)
	// Real server rejection, before either the fence or target mutation can commit.
	admin := db.Client().Database("admin")
	err := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: bson.M{"times": 1}}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"update"}, "errorCode": 2}}}).Err()
	if err != nil {
		t.Fatalf("Mongo must enable test commands for fault injection: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	})
	if err := repo.RevokeCurrentSession(t.Context(), current.TokenDigest, time.Now()); !errors.Is(err, port.ErrUnavailable) {
		t.Fatalf("failed write claimed success: %v", err)
	}
	var session SessionDocument
	if err := db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": current.SessionID}).Decode(&session); err != nil || session.RevokedAt != nil {
		t.Fatalf("failed transaction changed session: %v", err)
	}
	if err := repo.RevokeCurrentSession(t.Context(), current.TokenDigest, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CheckSession(t.Context(), current.TokenDigest, time.Now()); !errors.Is(err, port.ErrSessionInvalid) {
		t.Fatalf("retry did not revoke: %v", err)
	}
}

func TestSessionRevocationMongoUnknownCommitDoesNotClaimSuccess(t *testing.T) {
	_, db, current, _ := sessionRevocationFixture(t)
	repo, appName := sessionRevocationFaultRepository(t, db)
	admin := db.Client().Database("admin")
	err := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err()
	if err != nil {
		t.Fatal(err)
	}
	disable := func() {
		_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	}
	t.Cleanup(disable)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err := repo.RevokeCurrentSession(ctx, current.TokenDigest, time.Now()); !errors.Is(err, port.ErrUnavailable) {
		t.Fatalf("unknown commit claimed success: %v", err)
	}
	disable()
	if err := repo.RevokeCurrentSession(t.Context(), current.TokenDigest, time.Now()); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if _, err := repo.CheckSession(t.Context(), current.TokenDigest, time.Now()); !errors.Is(err, port.ErrSessionInvalid) {
		t.Fatalf("retry did not converge: %v", err)
	}
}

func sessionRevocationFaultRepository(t *testing.T, db *drivermongo.Database) (*AuthenticationRepository, string) {
	t.Helper()
	appName := "uc008-fault-" + db.Name()
	client, err := drivermongo.Connect(options.Client().ApplyURI(os.Getenv(mongoIntegrationURIEnvironment)).SetAppName(appName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	repo, err := NewAuthenticationRepository(client.Database(db.Name()), 100, 5)
	if err != nil {
		t.Fatal(err)
	}
	return repo, appName
}
