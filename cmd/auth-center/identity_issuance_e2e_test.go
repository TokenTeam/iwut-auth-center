package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	authv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	identityv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/identity"
	profilev1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	mongoadapter "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestE2E_IdentityIssuance_ProductionWire(t *testing.T) {
	uri := os.Getenv(mongoIntegrationURIEnv)
	if uri == "" {
		t.Skip("run make test-mongo")
	}
	serviceKey, callers := testServiceCallerRegistry(t)
	decoded, _ := base64.StdEncoding.DecodeString(callers)
	var registry map[string]map[string]any
	if err := json.Unmarshal(decoded, &registry); err != nil {
		t.Fatal(err)
	}
	source := registry["app-center"]
	registry["gateway"] = map[string]any{"status": "ACTIVE", "keys": source["keys"], "permissions": []string{"auth.identity.issue"}, "identityAudiences": []string{"iwut-auth-center", "iwut-app-center"}}
	registry["limited-gateway"] = map[string]any{"status": "ACTIVE", "keys": source["keys"], "permissions": []string{"auth.identity.issue"}, "identityAudiences": []string{"iwut-auth-center"}}
	encoded, _ := json.Marshal(registry)
	callers = base64.StdEncoding.EncodeToString(encoded)
	identityKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicDER, _ := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "public.pem")
	catalogFile := filepath.Join(dir, "catalog.json")
	for p, v := range map[string][]byte{keyFile: publicPEM, catalogFile: []byte(`{"definitions":[]}`)} {
		if err := os.WriteFile(p, v, 0600); err != nil {
			t.Fatal(err)
		}
	}
	keyMap, _ := json.Marshal(map[string]string{"identity-k1": keyFile})
	dbName := fmt.Sprintf("iwut_identity_wire_%d", time.Now().UnixNano())
	env := map[string]string{config.IdentityIssuanceEnabledEnv: "true", config.UserEndpointsEnabledEnv: "true", config.MongoURIEnv: uri, config.MongoDatabaseEnv: dbName, config.ServiceCallersEnv: callers, config.HTTPAddrEnv: reserveAddress(t), config.GRPCAddrEnv: reserveAddress(t), "AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h", "AUTH_ASSOC_KEY_VERSION": "v1", "AUTH_ASSOC_ENCRYPT_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "AUTH_ASSOC_LOOKUP_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "AUTH_PROFILE_CATALOG_FILE": catalogFile, "AUTH_USER_IDENTITY_ISSUER": "identity-test", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keyMap), "AUTH_USER_IDENTITY_SIGNING_KID": "identity-k1", "AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(identityKey)}))}
	configuration, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
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
	app, cleanup, err := wireApp(configuration)
	if err != nil {
		t.Fatal(err)
	}
	connection, stop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer stop()
	runReviewerFlow(t, env, connection, serviceKey, keyFile)
	client := identityv1.NewUserIdentityServiceClient(connection)
	auth := authv1.NewAuthenticationServiceClient(connection)
	device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	student := sha256.Sum256(deviceprotocol.Frame([]byte("iwut-student-association-v1"), []byte("0123456")))
	user, _ := registerUser(t, auth, device, student[:])
	callCtx := func(service, token string) context.Context {
		return metadata.AppendToOutgoingContext(serviceCallContext(t, t.Context(), serviceKey, service, "app-center-2026-01", "iwut-auth-center"), "x-iwut-session", token)
	}
	request := &identityv1.IssueUserIdentityFromSessionRequest{Audience: "iwut-auth-center"}
	verifier, err := transport.NewUserIdentityVerifier(configuration.UserEndpoints.UserIdentity)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.IssueUserIdentityFromSession(callCtx("gateway", user.Session.SessionToken), request)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(first.IdentityJws)
	if err != nil {
		t.Fatal("actual target verifier", err)
	}
	_ = verified
	payload := identityPayload(t, first.IdentityJws)
	if payload["sub"] != user.AuthId || payload["aud"] != "iwut-auth-center" || len(payload["permissions"].([]any)) != 0 || payload["developer_status"] != nil || int64(payload["exp"].(float64)) != first.ExpiresAtUnixSeconds {
		t.Fatal("unexpected ordinary user claims", payload)
	}
	profileCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", first.IdentityJws))
	if _, err := profilev1.NewUserProfileServiceClient(connection).GetOwnProfile(profileCtx, &profilev1.GetOwnProfileRequest{}); err != nil {
		t.Fatal("issued identity cannot authorize actual profile RPC", err)
	}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		aud  string
		code codes.Code
	}{
		{"no service", sessionCallContext(t.Context(), user.Session.SessionToken), "iwut-auth-center", codes.Unauthenticated},
		{"no session", serviceCallContext(t, t.Context(), serviceKey, "gateway", "app-center-2026-01", "iwut-auth-center"), "iwut-auth-center", codes.Unauthenticated},
		{"duplicate session", metadata.AppendToOutgoingContext(callCtx("gateway", user.Session.SessionToken), "x-iwut-session", user.Session.SessionToken), "iwut-auth-center", codes.Unauthenticated},
		{"malformed session", callCtx("gateway", "Bearer "+user.Session.SessionToken), "iwut-auth-center", codes.Unauthenticated},
		{"identity not session", metadata.AppendToOutgoingContext(serviceCallContext(t, t.Context(), serviceKey, "gateway", "app-center-2026-01", "iwut-auth-center"), "x-iwut-identity", first.IdentityJws), "iwut-auth-center", codes.Unauthenticated},
		{"no method permission", callCtx("scope-only", user.Session.SessionToken), "iwut-auth-center", codes.PermissionDenied},
		{"audience denied", callCtx("limited-gateway", user.Session.SessionToken), "iwut-app-center", codes.PermissionDenied},
		{"unknown audience", callCtx("gateway", user.Session.SessionToken), "unknown", codes.InvalidArgument},
		{"untrimmed audience", callCtx("gateway", user.Session.SessionToken), " iwut-auth-center", codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := client.IssueUserIdentityFromSession(tc.ctx, &identityv1.IssueUserIdentityFromSessionRequest{Audience: tc.aud})
			if status.Code(e) != tc.code || r != nil {
				t.Fatalf("%v %v", r, e)
			}
		})
	}
	// Unknown protobuf claims cannot turn this request into a caller-controlled token.
	unknown := &identityv1.IssueUserIdentityFromSessionRequest{Audience: "iwut-auth-center"}
	unknown.ProtoReflect().SetUnknown([]byte{0x12, 1, 'x'})
	if _, e := client.IssueUserIdentityFromSession(callCtx("gateway", user.Session.SessionToken), unknown); status.Code(e) != codes.InvalidArgument {
		t.Fatal(e)
	}
	mutate := func(fields bson.M) {
		t.Helper()
		if _, err := database.Collection(mongoadapter.PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": user.AuthId}, bson.M{"$set": fields, "$inc": bson.M{"permissionRevision": int64(1)}}); err != nil {
			t.Fatal(err)
		}
	}
	mutate(bson.M{"permissions": bson.A{"app.version.review", "auth.reviewer.manage", "future.permission"}, "developerStatus": "APPROVED"})
	for _, aud := range []string{"iwut-app-center", "iwut-auth-center"} {
		r, e := client.IssueUserIdentityFromSession(callCtx("gateway", user.Session.SessionToken), &identityv1.IssueUserIdentityFromSessionRequest{Audience: aud})
		if e != nil {
			t.Fatal(e)
		}
		p := identityPayload(t, r.IdentityJws)
		expected := "auth.reviewer.manage"
		if aud == "iwut-app-center" {
			expected = "app.version.review"
			if p["developer_status"] != "APPROVED" {
				t.Fatal(p)
			}
		} else if p["developer_status"] != nil {
			t.Fatal(p)
		}
		permissions := p["permissions"].([]any)
		if len(permissions) != 1 || permissions[0] != expected || p["jti"] == payload["jti"] {
			t.Fatal(p)
		}
	}
	mutate(bson.M{"permissions": bson.A{}, "developerStatus": nil})
	second, e := client.IssueUserIdentityFromSession(callCtx("gateway", user.Session.SessionToken), request)
	if e != nil || len(identityPayload(t, second.IdentityJws)["permissions"].([]any)) != 0 {
		t.Fatal("cached capabilities", e)
	}
	// Bounded local production signer + real RPC/Mongo performance observation.
	durations := make([]time.Duration, 20)
	start := time.Now()
	for i := range durations {
		callStart := time.Now()
		if _, e := client.IssueUserIdentityFromSession(callCtx("gateway", user.Session.SessionToken), request); e != nil {
			t.Fatal(e)
		}
		durations[i] = time.Since(callStart)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	t.Logf("LOCAL ONLY: 20 sequential full Wire/RPC/Mongo/RS256 issues; total=%s p50=%s p95=%s (includes test caller RSA signing)", time.Since(start), durations[9], durations[18])
	for _, fields := range []bson.M{{"accountStatus": "DISABLED"}, {"principalType": "SYSTEM"}} {
		mutate(fields)
		if _, e := client.IssueUserIdentityFromSession(callCtx("gateway", user.Session.SessionToken), request); status.Code(e) != codes.Unauthenticated {
			t.Fatal(e)
		}
		mutate(bson.M{"principalType": "USER", "accountStatus": "ACTIVE"})
	}
	expiry := time.Now().Add(5 * time.Second).Truncate(time.Second)
	if _, e := database.Collection(mongoadapter.SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": user.Session.SessionId}, bson.M{"$set": bson.M{"expiresAt": expiry}}); e != nil {
		t.Fatal(e)
	}
	near, e := client.IssueUserIdentityFromSession(callCtx("gateway", user.Session.SessionToken), request)
	if e != nil || near.GetExpiresAtUnixSeconds() != expiry.Unix() {
		t.Fatal("session expiry not bounded", e)
	}
	if _, e := auth.RevokeOwnCredential(sessionCallContext(t.Context(), user.Session.SessionToken), &authv1.RevokeOwnCredentialRequest{CredentialId: user.CredentialId}); e != nil {
		t.Fatal(e)
	}
	if _, e := client.IssueUserIdentityFromSession(callCtx("gateway", user.Session.SessionToken), request); status.Code(e) != codes.Unauthenticated {
		t.Fatal("revoked credential cached", e)
	}
	stop()
	// Disabled feature is absent, not an anonymously callable stub.
	configuration.IdentityIssuance = nil
	configuration.GRPCAddr = reserveAddress(t)
	disabled, disabledCleanup, e := wireApp(configuration)
	if e != nil {
		t.Fatal(e)
	}
	conn, disabledStop := startUserApp(t, disabled, disabledCleanup, configuration.GRPCAddr)
	defer disabledStop()
	if _, e := identityv1.NewUserIdentityServiceClient(conn).IssueUserIdentityFromSession(callCtx("gateway", user.Session.SessionToken), request); status.Code(e) != codes.Unimplemented {
		t.Fatal(e)
	}
}
func identityPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("not compact JWS")
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		t.Fatal(e)
	}
	var result map[string]any
	if e := json.Unmarshal(raw, &result); e != nil {
		t.Fatal(e)
	}
	return result
}
