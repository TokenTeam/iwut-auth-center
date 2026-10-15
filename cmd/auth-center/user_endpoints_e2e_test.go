package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	authv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	scopev1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/scope_catalog"
	profilev1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	emailpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	"github.com/go-kratos/kratos/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	mongoadapter "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
)

func TestE2E_UserEndpoints_ProductionWireAndColdRotation(t *testing.T) {
	uri := os.Getenv(mongoIntegrationURIEnv)
	if uri == "" {
		t.Skip("run make test-mongo")
	}
	serviceKey, callers := testServiceCallerRegistry(t)
	// Separate issuer key: this is a fixture for the already defined trusted-user
	// boundary, not an implementation of the future Session-to-JWS issuer.
	identityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	publicDER, err := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "identity.pem")
	catalogFile := filepath.Join(dir, "profile.json")
	for path, data := range map[string][]byte{keyFile: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), catalogFile: []byte(`{"definitions":[{"key":"test.nickname","label":"Test nickname","description":"Fixture only","valueType":"STRING","constraints":{"maxLength":32}}]}`)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	keysJSON, _ := json.Marshal(map[string]string{"test": keyFile})
	dbName := fmt.Sprintf("iwut_user_wire_%d", time.Now().UnixNano())
	env := map[string]string{config.UserEndpointsEnabledEnv: "true", config.MongoURIEnv: uri, config.MongoDatabaseEnv: dbName, config.ServiceCallersEnv: callers, config.HTTPAddrEnv: reserveAddress(t), config.GRPCAddrEnv: reserveAddress(t), "AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h", "AUTH_ASSOC_KEY_VERSION": "v1", "AUTH_PROFILE_CATALOG_FILE": catalogFile, "AUTH_USER_IDENTITY_ISSUER": "test-auth-issuer", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keysJSON)}
	setKeys := func(version string, enc, lookup byte) {
		env["AUTH_ASSOC_KEY_VERSION"] = version
		env["AUTH_ASSOC_ENCRYPT_KEY"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{enc}, 32))
		env["AUTH_ASSOC_LOOKUP_KEY"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{lookup}, 32))
	}
	setKeys("v1", 1, 2)
	capture := enableEmailRegistrationFixture(t, env)
	load := func() config.Config {
		t.Helper()
		c, e := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	mongoClient, err := mongoadapter.NewClient(uri)
	if err != nil {
		t.Fatal(err)
	}
	database := mongoClient.Database(dbName)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = database.Drop(ctx)
		_ = mongoClient.Disconnect(ctx)
	})

	app, cleanup, err := wireApp(load())
	if err != nil {
		t.Fatal(err)
	}
	connection, stop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	authClient := authv1.NewAuthenticationServiceClient(connection)
	profileClient := profilev1.NewUserProfileServiceClient(connection)
	device, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	studentToken := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-student-association-v1"), []byte("0122256789101")))
	first, proof := registerUser(t, connection, device, studentToken[:])
	if first.AuthId == "" || first.CredentialId == "" || first.Session.AuthId != first.AuthId {
		t.Fatal("registration identity mismatch")
	}
	if _, err := emailpb.NewEmailAccountServiceClient(connection).CompleteEmailRegistration(t.Context(), proof); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("registration replay: %v", err)
	}
	sessionContext := sessionCallContext(t.Context(), first.Session.SessionToken)
	if _, err := profileClient.GetOwnProfile(sessionContext, &profilev1.GetOwnProfileRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("session bypassed user identity: %v", err)
	}
	profileContext := userCallContext(t, identityKey, first.AuthId)
	snapshot, err := profileClient.GetOwnProfile(profileContext, &profilev1.GetOwnProfileRequest{})
	if err != nil || snapshot.GetRevision() != 1 || len(snapshot.GetEntries()) != 0 {
		t.Fatalf("initial profile: %v %v", snapshot, err)
	}
	schema, err := profileClient.GetProfileEditingSchema(profileContext, &profilev1.GetProfileEditingSchemaRequest{})
	if err != nil || len(schema.GetDefinitions()) != 1 {
		t.Fatalf("schema: %v %v", schema, err)
	}
	revision := int64(1)
	edit := &profilev1.EditOwnProfileRequest{ExpectedRevision: &revision, Set: []*profilev1.ProfileFieldAssignment{{Key: "test.nickname", Value: &profilev1.ProfileValue{Value: &profilev1.ProfileValue_StringValue{StringValue: "Alice"}}}}}
	edited, err := profileClient.EditOwnProfile(profileContext, edit)
	if err != nil || !edited.GetChanged() || edited.GetProfile().GetRevision() != 2 {
		t.Fatalf("edit: %v %v", edited, err)
	}
	if _, err := profileClient.EditOwnProfile(profileContext, edit); status.Code(err) != codes.Aborted {
		t.Fatalf("stale revision: %v", err)
	}
	scopeClient := scopev1.NewScopeCatalogClient(connection)
	if _, err := scopeClient.GetScopeCatalogSnapshot(sessionContext, &scopev1.GetScopeCatalogSnapshotRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("session bypassed internal JWS: %v", err)
	}
	internalContext := serviceCallContext(t, t.Context(), serviceKey, "app-center", "app-center-2026-01", "iwut-auth-center")
	if _, err := scopeClient.GetScopeCatalogSnapshot(internalContext, &scopev1.GetScopeCatalogSnapshotRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := authClient.RevokeOwnCredential(profileContext, &authv1.RevokeOwnCredentialRequest{CredentialId: first.CredentialId}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("user JWS bypassed session: %v", err)
	}

	login := loginUser(t, authClient, device, first.CredentialId)
	if login.AuthId != first.AuthId || login.CredentialId != first.CredentialId || login.SessionToken == first.Session.SessionToken {
		t.Fatal("login identity mismatch")
	}
	for i := 0; i < 2; i++ {
		if _, err := authClient.RevokeCurrentSession(sessionContext, &authv1.RevokeCurrentSessionRequest{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := authClient.RevokeOwnCredential(sessionContext, &authv1.RevokeOwnCredentialRequest{CredentialId: first.CredentialId}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked session still authorizes: %v", err)
	}
	if _, err := authClient.RevokeOwnCredential(sessionCallContext(t.Context(), login.SessionToken), &authv1.RevokeOwnCredentialRequest{CredentialId: "87654321-1234-4234-8234-123456789abc"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-current credential bypassed dedicated reauthentication: %v", err)
	}
	if _, err := authClient.RevokeOwnCredential(sessionCallContext(t.Context(), login.SessionToken), &authv1.RevokeOwnCredentialRequest{CredentialId: first.CredentialId}); err != nil {
		t.Fatal(err)
	}
	if _, err := authClient.RevokeOwnCredential(sessionCallContext(t.Context(), login.SessionToken), &authv1.RevokeOwnCredentialRequest{CredentialId: first.CredentialId}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked credential session still authorizes: %v", err)
	}
	rejected, err := authClient.BeginDeviceLogin(t.Context(), &authv1.BeginDeviceLoginRequest{CredentialLocator: &authv1.BeginDeviceLoginRequest_CredentialId{CredentialId: first.CredentialId}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authClient.CompleteDeviceLogin(t.Context(), &authv1.CompleteDeviceLoginRequest{OperationId: rejected.OperationId, Proof: &authv1.CredentialProof{Signature: signDevice(t, device, rejected.SigningPayload)}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked credential login: %v", err)
	}
	stop()

	// Retired association ENV are ignored, even malformed leftovers cannot
	// trigger migration or prevent an otherwise valid startup.
	for _, suffix := range []string{"KEY_VERSION", "ENCRYPT_KEY", "LOOKUP_KEY"} {
		env["AUTH_ASSOC_PREVIOUS_"+suffix] = env["AUTH_ASSOC_"+suffix]
	}
	setKeys("v2", 3, 4)
	env[config.GRPCAddrEnv] = reserveAddress(t)
	rememberRegistrationSMTP(t, env[config.GRPCAddrEnv], capture)
	rotatedApp, rotatedCleanup, err := wireApp(load())
	if err != nil {
		t.Fatal(err)
	}
	// Construction ran the gate, but no listener was started for this intermediate process.
	_ = rotatedApp
	rotatedCleanup()
	for _, suffix := range []string{"KEY_VERSION", "ENCRYPT_KEY", "LOOKUP_KEY"} {
		delete(env, "AUTH_ASSOC_PREVIOUS_"+suffix)
	}
	currentApp, currentCleanup, err := wireApp(load())
	if err != nil {
		t.Fatal(err)
	}
	currentConnection, currentStop := startUserApp(t, currentApp, currentCleanup, env[config.GRPCAddrEnv])
	defer currentStop()
	secondDevice, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := registerUser(t, currentConnection, secondDevice, studentToken[:])
	if second.AuthId == first.AuthId {
		t.Fatal("association silently merged accounts")
	}
	count, err := database.Collection(mongoadapter.AssociationCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil || count != 0 {
		t.Fatalf("retired association written: %d %v", count, err)
	}
	count, err = database.Collection(mongoadapter.AssociationMemberCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil || count != 0 {
		t.Fatalf("retired association member written: %d %v", count, err)
	}
	runHTTPUserFlow(t, "http://"+env[config.HTTPAddrEnv], identityKey, capture)
	currentStop()
	setKeys("v2", 5, 6)
	env["AUTH_ASSOC_ENCRYPT_KEY"] = "malformed-retired-variable"
	if _, finalCleanup, err := wireApp(load()); err != nil {
		t.Fatal("retired keys blocked startup", err)
	} else {
		finalCleanup()
	}
}

func startUserApp(t *testing.T, app *kratos.App, cleanup func(), address string) (*grpc.ClientConn, func()) {
	t.Helper()
	done := make(chan struct{})
	var runErr error
	go func() { runErr = app.Run(); close(done) }()
	connection := dialGRPC(t, address, done, &runErr)
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = connection.Close()
		if err := app.Stop(); err != nil {
			t.Error(err)
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("app failed to stop")
		}
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.Error(runErr)
		}
		cleanup()
	}
	t.Cleanup(stop)
	return connection, stop
}
func sessionCallContext(ctx context.Context, token string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("x-iwut-session", token))
}
func signDevice(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func loginUser(t *testing.T, client authv1.AuthenticationServiceClient, key *ecdsa.PrivateKey, credentialID string) *authv1.SessionEstablished {
	t.Helper()
	challenge, err := client.BeginDeviceLogin(t.Context(), &authv1.BeginDeviceLoginRequest{CredentialLocator: &authv1.BeginDeviceLoginRequest_CredentialId{CredentialId: credentialID}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CompleteDeviceLogin(t.Context(), &authv1.CompleteDeviceLoginRequest{OperationId: challenge.OperationId, Proof: &authv1.CredentialProof{Signature: signDevice(t, key, challenge.SigningPayload)}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func userCallContext(t *testing.T, key *rsa.PrivateKey, authID string) context.Context {
	t.Helper()
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"})
	claims, _ := json.Marshal(map[string]any{"account_revision": "1", "iss": "test-auth-issuer", "sub": authID, "aud": "iwut-auth-center", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": fmt.Sprint(now.UnixNano())})
	body := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	hash := sha256.Sum256([]byte(body))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", body+"."+base64.RawURLEncoding.EncodeToString(signature)))
}
