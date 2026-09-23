package mongo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/adapter/identitysigner"
	"iwut-auth-center/internal/identity/domain"
	identityport "iwut-auth-center/internal/identity/port"
	"iwut-auth-center/internal/identity/usecase"
	"sync"
	"testing"
	"time"
)

type identitySignerFunc func(context.Context, domain.Claims) (string, error)

func (f identitySignerFunc) Sign(ctx context.Context, c domain.Claims) (string, error) {
	return f(ctx, c)
}
func identityFixture(t *testing.T) (*IdentityRepository, *drivermongo.Database, SessionDocument, string, identityport.Tokens, identityport.Signer) {
	t.Helper()
	authentication, db, session, _ := sessionRevocationFixture(t)
	_, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": session.AuthID}, bson.M{"$set": bson.M{"permissions": bson.A{"app.version.review"}, "permissionRevision": int64(1), "developerStatus": "APPROVED"}})
	if err != nil {
		t.Fatal(err)
	}
	protocol, _ := deviceprotocol.New("test")
	token, digest, _ := protocol.NewSessionToken()
	session.TokenDigest = digest
	_, err = db.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": session.SessionID}, bson.M{"$set": bson.M{"tokenDigest": digest}})
	if err != nil {
		t.Fatal(err)
	}
	repo, _ := NewIdentityRepository(authentication)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := identitysigner.New("test", "key", key)
	return repo, db, session, token, protocol, signer
}
func TestIdentityMongoSigningFailureRollsBackUsageAndFence(t *testing.T) {
	repo, db, session, token, tokens, _ := identityFixture(t)
	before := func() SessionDocument {
		var s SessionDocument
		if err := db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": session.SessionID}).Decode(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}()
	service, _ := usecase.New(repo, identitySignerFunc(func(context.Context, domain.Claims) (string, error) { return "", errors.New("signing failure") }), tokens, time.Minute)
	if result, err := service.Issue(t.Context(), token, domain.AppAudience, []string{domain.AppAudience}); !errors.Is(err, domain.ErrUnavailable) || result.JWS != "" {
		t.Fatal(result, err)
	}
	var after bson.Raw
	if err := db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": session.SessionID}).Decode(&after); err != nil {
		t.Fatal(err)
	}
	if after.Lookup("lastUsedAt").DateTime() != before.LastUsedAt.UnixMilli() || after.Lookup("authenticationFence").Type != 0 {
		t.Fatal("failed signing committed usage")
	}
}
func TestIdentityMongoConcurrentCapabilitiesAndRevocation(t *testing.T) {
	repo, db, session, token, tokens, signer := identityFixture(t)
	service, _ := usecase.New(repo, signer, tokens, time.Minute)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := service.Issue(t.Context(), token, domain.AppAudience, []string{domain.AppAudience})
			if err != nil {
				t.Errorf("concurrent issue %v", err)
			}
		}()
	}
	// Direct writer deliberately does not use the global authentication fence.
	// Issuance touches the principal too, so retries cannot confirm stale abilities.
	if _, err := db.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": session.AuthID}, bson.M{"$set": bson.M{"permissions": bson.A{}, "developerStatus": "SUSPENDED"}, "$inc": bson.M{"permissionRevision": int64(1)}}); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for range 3 {
		if err := repo.WithSession(t.Context(), session.TokenDigest, func(s domain.Snapshot, _ time.Time) error {
			if len(s.Permissions) != 0 || s.DeveloperStatus != "SUSPENDED" || s.PermissionRevision != 2 {
				t.Fatal("stale snapshot", s)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := service.Issue(t.Context(), token, domain.AppAudience, []string{domain.AppAudience})
			if err != nil && !errors.Is(err, domain.ErrSessionInvalid) {
				t.Errorf("concurrent revoke %v", err)
			}
		}()
	}
	if err := repo.authentication.RevokeCurrentSession(t.Context(), session.TokenDigest, time.Now()); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		r, e := service.Issue(t.Context(), token, domain.AppAudience, []string{domain.AppAudience})
		if !errors.Is(e, domain.ErrSessionInvalid) || r.JWS != "" {
			t.Fatal("cached revoked session", r, e)
		}
	}
	wg.Wait()
}
func TestIdentityMongoDamagedRecordsFailUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name, collection, field string
		value                   any
	}{{"permissions null", PrincipalCollection, "permissions", nil}, {"duplicate", PrincipalCollection, "permissions", bson.A{"x", "x"}}, {"revision int32", PrincipalCollection, "permissionRevision", int32(1)}, {"revision zero", PrincipalCollection, "permissionRevision", int64(0)}, {"status", PrincipalCollection, "developerStatus", "UNKNOWN"}, {"principal", PrincipalCollection, "principalType", "ALIEN"}, {"session time", SessionCollection, "lastUsedAt", "now"}, {"credential key", CredentialCollection, "publicKey", []byte{4}}} {
		t.Run(tc.name, func(t *testing.T) {
			repo, db, session, token, tokens, signer := identityFixture(t)
			filter := bson.M{"authId": session.AuthID}
			if tc.collection == SessionCollection {
				filter = bson.M{"sessionId": session.SessionID}
			}
			if _, err := db.Collection(tc.collection).UpdateOne(t.Context(), filter, bson.M{"$set": bson.M{tc.field: tc.value}}); err != nil {
				t.Fatal(err)
			}
			service, _ := usecase.New(repo, signer, tokens, time.Minute)
			r, e := service.Issue(t.Context(), token, domain.AuthAudience, []string{domain.AuthAudience})
			if !errors.Is(e, domain.ErrUnavailable) || r.JWS != "" {
				t.Fatal(r, e)
			}
		})
	}
}
func TestIdentityMongoUnconfirmedCommitCannotReleaseSignedCandidate(t *testing.T) {
	_, db, session, token, tokens, signer := identityFixture(t)
	authentication, appName := sessionRevocationFaultRepository(t, db)
	repo, _ := NewIdentityRepository(authentication)
	service, _ := usecase.New(repo, signer, tokens, time.Minute)
	admin := db.Client().Database("admin")
	if err := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	off := func() {
		_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	}
	t.Cleanup(off)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	r, e := service.Issue(ctx, token, domain.AuthAudience, []string{domain.AuthAudience})
	if e == nil || r.JWS != "" {
		t.Fatal("unknown commit released candidate", r, e)
	}
	off()
	var stored SessionDocument
	if err := db.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": session.SessionID}).Decode(&stored); err != nil {
		t.Fatal(err)
	}
	if !stored.LastUsedAt.Equal(session.LastUsedAt) {
		t.Fatal("injected rejected commit changed LRU")
	}
	if r, e := service.Issue(t.Context(), token, domain.AuthAudience, []string{domain.AuthAudience}); e != nil || r.JWS == "" {
		t.Fatal("fresh retry failed", r, e)
	}
}
