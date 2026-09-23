package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	developerstatusv1 "iwut-auth-center/api/gen/go/auth_center/v1/developer_status"
	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
	systemprincipalv1 "iwut-auth-center/api/gen/go/auth_center/v1/system_principal"
	"iwut-auth-center/internal/adapter/catalog"
	mongoadapter "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
)

const mongoIntegrationURIEnv = "MONGODB_INTEGRATION_URI"

func TestE2E_UCAUTH001And002_RealProvidersOverRealGRPC(t *testing.T) {
	mongoURI := os.Getenv(mongoIntegrationURIEnv)
	if mongoURI == "" {
		t.Skipf("set %s or run scripts/test-mongo-integration.sh", mongoIntegrationURIEnv)
	}
	databaseName := fmt.Sprintf("iwut_auth_center_e2e_%d", time.Now().UnixNano())
	seedPrincipalFixtures(t, mongoURI, databaseName)
	serviceKey, serviceCallers := testServiceCallerRegistry(t)

	address := reserveAddress(t)
	configuration, err := config.Load(func(key string) (string, bool) {
		switch key {
		case config.HTTPAddrEnv:
			return "127.0.0.1:0", true
		case config.GRPCAddrEnv:
			return address, true
		case config.MongoURIEnv:
			return mongoURI, true
		case config.MongoDatabaseEnv:
			return databaseName, true
		case config.ServiceCallersEnv:
			return serviceCallers, true
		default:
			return "", false
		}
	})
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	app, cleanup, err := wireApp(configuration)
	if err != nil {
		t.Fatalf("wireApp() error = %v", err)
	}
	t.Cleanup(cleanup)

	runDone := make(chan struct{})
	var runErr error
	go func() {
		runErr = app.Run()
		close(runDone)
	}()
	t.Cleanup(func() {
		if err := app.Stop(); err != nil {
			t.Errorf("app.Stop() error = %v", err)
		}
		select {
		case <-runDone:
		case <-time.After(10 * time.Second):
			t.Error("app.Run() did not stop")
		}
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.Errorf("app.Run() error = %v", runErr)
		}
	})

	connection := dialGRPC(t, address, runDone, &runErr)
	t.Cleanup(func() { _ = connection.Close() })
	client := scopecatalogv1.NewScopeCatalogClient(connection)
	if _, err := client.GetScopeCatalogSnapshot(t.Context(), &scopecatalogv1.GetScopeCatalogSnapshotRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("GetScopeCatalogSnapshot() without service identity code = %v, want Unauthenticated", status.Code(err))
	}
	callContext := serviceCallContext(t, t.Context(), serviceKey, "app-center", "app-center-2026-01", "iwut-auth-center")
	response, err := client.GetScopeCatalogSnapshot(callContext, &scopecatalogv1.GetScopeCatalogSnapshotRequest{})
	if err != nil {
		t.Fatalf("GetScopeCatalogSnapshot() error = %v", err)
	}
	if response.GetRevision() != catalog.HardcodedRevision || !response.GetGeneratedAt().AsTime().Equal(catalog.HardcodedGeneratedAt) {
		t.Fatalf("snapshot metadata = (%d, %v)", response.GetRevision(), response.GetGeneratedAt())
	}
	want := []struct {
		name        string
		requestable bool
	}{
		{name: "legacy.profile", requestable: false},
		{name: "profile.basic", requestable: true},
		{name: "schedule.read", requestable: true},
	}
	if len(response.GetScopes()) != len(want) {
		t.Fatalf("scope count = %d, want %d", len(response.GetScopes()), len(want))
	}
	for index, expected := range want {
		got := response.GetScopes()[index]
		if got.GetName() != expected.name || got.GetRequestable() != expected.requestable {
			t.Fatalf("scope[%d] = (%q, %t), want (%q, %t)", index, got.GetName(), got.GetRequestable(), expected.name, expected.requestable)
		}
	}

	developerClient := developerstatusv1.NewDeveloperStatusDirectoryClient(connection)
	limitedContext := serviceCallContext(t, t.Context(), serviceKey, "scope-only", "app-center-2026-01", "iwut-auth-center")
	if _, err := developerClient.BatchGetDeveloperStatuses(limitedContext, &developerstatusv1.BatchGetDeveloperStatusesRequest{
		AuthIds: []string{"developer-approved"},
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("BatchGetDeveloperStatuses() without permission code = %v, want PermissionDenied", status.Code(err))
	}
	statusResponse, err := developerClient.BatchGetDeveloperStatuses(callContext, &developerstatusv1.BatchGetDeveloperStatusesRequest{
		AuthIds: []string{"developer-suspended", "developer-approved"},
	})
	if err != nil {
		t.Fatalf("BatchGetDeveloperStatuses() error = %v", err)
	}
	statusWant := []struct {
		authID string
		status developerstatusv1.DeveloperStatus
	}{
		{authID: "developer-suspended", status: developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_SUSPENDED},
		{authID: "developer-approved", status: developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_APPROVED},
	}
	if len(statusResponse.GetEntries()) != len(statusWant) {
		t.Fatalf("developer status count = %d, want %d", len(statusResponse.GetEntries()), len(statusWant))
	}
	for index, expected := range statusWant {
		entry := statusResponse.GetEntries()[index]
		if entry.GetAuthId() != expected.authID || entry.GetDeveloperStatus() != expected.status {
			t.Fatalf("developer status[%d] = (%q, %v), want (%q, %v)", index, entry.GetAuthId(), entry.GetDeveloperStatus(), expected.authID, expected.status)
		}
	}

	for _, authID := range []string{"missing-user", "ordinary-user", "system-reviewer"} {
		_, err := developerClient.BatchGetDeveloperStatuses(callContext, &developerstatusv1.BatchGetDeveloperStatusesRequest{
			AuthIds: []string{authID},
		})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("BatchGetDeveloperStatuses(%q) code = %v, want NotFound", authID, status.Code(err))
		}
	}

	systemClient := systemprincipalv1.NewSystemPrincipalDirectoryClient(connection)
	first, err := systemClient.ResolveSystemPrincipal(callContext, &systemprincipalv1.ResolveSystemPrincipalRequest{
		Purpose: systemprincipalv1.SystemPrincipalPurpose_SYSTEM_PRINCIPAL_PURPOSE_APP_CENTER_REVIEW_AUTO_REJECTION,
	})
	if err != nil {
		t.Fatalf("ResolveSystemPrincipal() error = %v", err)
	}
	second, err := systemClient.ResolveSystemPrincipal(callContext, &systemprincipalv1.ResolveSystemPrincipalRequest{
		Purpose: systemprincipalv1.SystemPrincipalPurpose_SYSTEM_PRINCIPAL_PURPOSE_APP_CENTER_REVIEW_AUTO_REJECTION,
	})
	if err != nil {
		t.Fatalf("ResolveSystemPrincipal() second error = %v", err)
	}
	if first.GetAuthId() == "" || first.GetAuthId() != second.GetAuthId() {
		t.Fatalf("system principal auth IDs = (%q, %q), want one stable non-empty ID", first.GetAuthId(), second.GetAuthId())
	}
}

func testServiceCallerRegistry(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate service key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal service public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	registry := map[string]any{
		"app-center": map[string]any{
			"status": "ACTIVE",
			"keys": map[string]any{
				"app-center-2026-01": map[string]string{"publicKeyPemB64": base64.StdEncoding.EncodeToString(publicPEM)},
			},
			"permissions":             []string{"auth.scope-catalog.read", "auth.developer-status.read", "auth.system-principal.resolve"},
			"systemPrincipalPurposes": []string{"app-center.review-auto-rejection"},
		},
		"scope-only": map[string]any{
			"status": "ACTIVE",
			"keys": map[string]any{
				"app-center-2026-01": map[string]string{"publicKeyPemB64": base64.StdEncoding.EncodeToString(publicPEM)},
			},
			"permissions":             []string{"auth.scope-catalog.read"},
			"systemPrincipalPurposes": []string{},
		},
	}
	raw, err := json.Marshal(registry)
	if err != nil {
		t.Fatalf("marshal service caller registry: %v", err)
	}
	return privateKey, base64.StdEncoding.EncodeToString(raw)
}

func serviceCallContext(t *testing.T, ctx context.Context, key *rsa.PrivateKey, serviceID, kid, audience string) context.Context {
	t.Helper()
	now := time.Now().UTC()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	claims, _ := json.Marshal(map[string]any{
		"iss": serviceID, "sub": serviceID, "aud": audience,
		"iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(), "exp": now.Add(time.Minute).Unix(),
		"jti": fmt.Sprintf("e2e-%d", now.UnixNano()),
	})
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(encodedHeader + "." + encodedClaims))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign service JWS: %v", err)
	}
	token := encodedHeader + "." + encodedClaims + "." + base64.RawURLEncoding.EncodeToString(signature)
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
}

func seedPrincipalFixtures(t *testing.T, uri, databaseName string) {
	t.Helper()
	client, err := mongoadapter.NewClient(uri)
	if err != nil {
		t.Fatalf("connect fixture MongoDB: %v", err)
	}
	database, err := mongoadapter.NewDatabase(client, databaseName)
	if err != nil {
		t.Fatalf("select fixture database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = database.Drop(ctx)
		_ = client.Disconnect(ctx)
	})
	if err := mongoadapter.EnsurePrincipalSchema(t.Context(), database); err != nil {
		t.Fatalf("ensure principal schema: %v", err)
	}
	_, err = database.Collection(mongoadapter.PrincipalCollection).InsertMany(t.Context(), []any{
		bson.M{"authId": "developer-approved", "principalType": "USER", "developerStatus": "APPROVED"},
		bson.M{"authId": "developer-suspended", "principalType": "USER", "developerStatus": "SUSPENDED"},
		bson.M{"authId": "ordinary-user", "principalType": "USER", "developerStatus": nil},
		bson.M{"authId": "system-reviewer", "principalType": "SYSTEM"},
	})
	if err != nil {
		t.Fatalf("insert principal fixtures: %v", err)
	}
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release address: %v", err)
	}
	return address
}

func dialGRPC(t *testing.T, address string, runDone <-chan struct{}, runErr *error) *grpc.ClientConn {
	t.Helper()
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	connection.Connect()
	deadline := time.Now().Add(15 * time.Second)
	for {
		state := connection.GetState()
		if state == connectivity.Ready {
			return connection
		}
		select {
		case <-runDone:
			_ = connection.Close()
			t.Fatalf("app.Run() exited before gRPC was ready: %v", *runErr)
		default:
		}
		if time.Now().After(deadline) {
			_ = connection.Close()
			t.Fatalf("gRPC did not become ready; state = %v", state)
		}
		waitCtx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		connection.WaitForStateChange(waitCtx, state)
		cancel()
	}
}
