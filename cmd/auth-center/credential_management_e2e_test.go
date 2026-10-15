package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/credential_management"
	loginpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_login"
	emailpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestE2E_CredentialManagement_ProductionWire(t *testing.T) {
	uri := os.Getenv(mongoIntegrationURIEnv)
	if uri == "" {
		t.Skip("run make test-mongo")
	}
	_, callers := testServiceCallerRegistry(t)
	issuer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&issuer.PublicKey)
	dir := t.TempDir()
	keyFile, catalog := filepath.Join(dir, "key.pem"), filepath.Join(dir, "catalog.json")
	for path, data := range map[string][]byte{keyFile: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), catalog: []byte(`{"definitions":[]}`)} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	keys, _ := json.Marshal(map[string]string{"test": keyFile})
	dbName := "uc032_wire_" + uuid.NewString()
	env := map[string]string{config.UserEndpointsEnabledEnv: "true", config.MongoURIEnv: uri, config.MongoDatabaseEnv: dbName, config.ServiceCallersEnv: callers, config.HTTPAddrEnv: reserveAddress(t), config.GRPCAddrEnv: reserveAddress(t), "AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h", "AUTH_PROFILE_CATALOG_FILE": catalog, "AUTH_USER_IDENTITY_ISSUER": "credential-test", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keys), "AUTH_CREDENTIAL_MANAGEMENT_ENABLED": "true", "AUTH_CREDENTIAL_MANAGEMENT_ACCOUNT_PER_MINUTE": "1000", "AUTH_EMAIL_LOGIN_ENABLED": "true", "AUTH_EMAIL_LOGIN_CODE_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	capture := enableEmailRegistrationFixture(t, env)
	load := func() config.Config {
		c, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	clientDB, err := ma.NewClient(uri)
	if err != nil {
		t.Fatal(err)
	}
	db := clientDB.Database(dbName)
	t.Cleanup(func() { _ = db.Drop(context.Background()); _ = clientDB.Disconnect(context.Background()) })
	app, cleanup, err := wireApp(load())
	if err != nil {
		t.Fatal(err)
	}
	conn, stop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer stop()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registered, _ := registerUser(t, conn, key, nil)
	ctx := sessionCallContext(t.Context(), registered.Session.SessionToken)
	service := pb.NewCredentialManagementServiceClient(conn)
	email, err := emailpb.NewEmailAccountServiceClient(conn).GetOwnEmails(ctx, &emailpb.GetOwnEmailsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	// Recovery uses the real verified directory, TLS SMTP and new-device proof.
	// Only the isolated send-budget is reset so this test does not wait 60 seconds.
	if _, err = db.Collection(ma.EmailQuotaCollection).DeleteMany(t.Context(), bson.M{}); err != nil {
		t.Fatal(err)
	}
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	login := loginpb.NewEmailLoginServiceClient(conn)
	challenge, err := login.BeginEmailLogin(t.Context(), &loginpb.BeginEmailLoginRequest{RequestId: uuid.NewString(), Email: email.Emails[0].Email, CredentialProposal: &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: elliptic.Marshal(elliptic.P256(), otherKey.X, otherKey.Y)}})
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(capture.Next(t).Body)
	if len(match) != 2 {
		t.Fatal("missing recovery code")
	}
	recovered, err := login.CompleteEmailLogin(t.Context(), &loginpb.CompleteEmailLoginRequest{OperationId: challenge.OperationId, Code: match[1], Proof: &authpb.CredentialProof{Signature: signDevice(t, otherKey, challenge.SigningPayload)}})
	if err != nil {
		t.Fatal(err)
	}
	target := recovered.CredentialId
	otherCtx := sessionCallContext(t.Context(), recovered.Session.SessionToken)
	before, err := db.Collection(ma.SessionCollection).FindOne(t.Context(), bson.M{"sessionId": registered.Session.SessionId}).Raw()
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.ListOwnCredentials(ctx, &pb.ListOwnCredentialsRequest{})
	if err != nil || len(page.Credentials) != 2 {
		t.Fatal(page, err)
	}
	if _, err = service.ListOwnCredentials(otherCtx, &pb.ListOwnCredentialsRequest{}); err != nil {
		t.Fatal("email-source Session rejected", err)
	}
	label := "Laptop"
	rev := int64(0)
	out, err := service.SetOwnCredentialLabel(ctx, &pb.SetOwnCredentialLabelRequest{CredentialId: target, Label: &label, ExpectedLabelRevision: &rev})
	if err != nil || out.LabelRevision != 1 {
		t.Fatal(out, err)
	}
	httpCall := func(path, body, token string, want int) []byte {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, "http://"+env[config.HTTPAddrEnv]+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("x-iwut-session", token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s: %d want%d %s", path, resp.StatusCode, want, data)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable credentials")
		}
		return data
	}
	data := httpCall("/v1/users/me/credentials:list", "{}", registered.Session.SessionToken, 200)
	if !bytes.Contains(data, []byte("Laptop")) || bytes.Contains(data, []byte("publicKey")) {
		t.Fatal("invalid projection")
	}
	httpCall("/v1/users/me/credentials:set-label", `{"credentialId":"`+target+`","label":"","expectedLabelRevision":"1"}`, registered.Session.SessionToken, 200)
	for _, body := range []string{`{"credentialId":"` + target + `","expectedLabelRevision":"2"}`, `{"credentialId":"` + target + `","label":null,"expectedLabelRevision":"2"}`, `{"credentialId":"` + target + `","label":"secret-probe","expectedLabelRevision":2}`, `{"pageSize":10,"pageSize":20}`, `{"unknown":"secret-probe"}`} {
		path := "/v1/users/me/credentials:set-label"
		if strings.Contains(body, "pageSize") || strings.Contains(body, "unknown") {
			path = "/v1/users/me/credentials:list"
		}
		response := httpCall(path, body, registered.Session.SessionToken, 400)
		if bytes.Contains(response, []byte("secret-probe")) {
			t.Fatal("input echoed")
		}
	}
	httpCall("/v1/users/me/credentials:list", "{}", "", 401)
	if _, err = authpb.NewAuthenticationServiceClient(conn).RevokeOwnCredential(ctx, &authpb.RevokeOwnCredentialRequest{CredentialId: target}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("legacy bypass", err)
	}
	// The legacy UC009 middleware deliberately performs its ordinary Session
	// touch. Only the four new management commands promise no LRU mutation.
	before, err = db.Collection(ma.SessionCollection).FindOne(t.Context(), bson.M{"sessionId": registered.Session.SessionId}).Raw()
	if err != nil {
		t.Fatal(err)
	}
	started, err := service.BeginOtherCredentialRevocation(ctx, &pb.BeginOtherCredentialRevocationRequest{RequestId: uuid.NewString(), TargetCredentialId: target})
	if err != nil {
		t.Fatal(err)
	}
	complete := &pb.CompleteOtherCredentialRevocationRequest{OperationId: started.OperationId, SignatureDer: signDevice(t, key, started.SigningPayload)}
	if _, err = service.CompleteOtherCredentialRevocation(ctx, complete); status.Code(err) != codes.InvalidArgument {
		t.Fatal("omitted password", err)
	}
	complete.CurrentPassword = "wrong current password"
	if _, err = service.CompleteOtherCredentialRevocation(ctx, complete); status.Code(err) != codes.Unauthenticated {
		t.Fatal("wrong password", err)
	}
	complete.CurrentPassword = "a long fixture password 123"
	body, _ := protojson.Marshal(complete)
	httpCall("/v1/users/me/credentials/revocation:complete", string(body), registered.Session.SessionToken, 200)
	if _, err = service.CompleteOtherCredentialRevocation(ctx, complete); err != nil {
		t.Fatal("native completion replay", err)
	}
	if _, err = service.ListOwnCredentials(otherCtx, &pb.ListOwnCredentialsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("revoked key retained Session", err)
	}
	after, err := db.Collection(ma.SessionCollection).FindOne(t.Context(), bson.M{"sessionId": registered.Session.SessionId}).Raw()
	if err != nil || !before.Lookup("lastUsedAt").Time().Equal(after.Lookup("lastUsedAt").Time()) {
		t.Fatal("management touched LRU", err)
	}
	// Default-closed route, while persisted operations keep bounded maintenance.
	stop()
	env["AUTH_CREDENTIAL_MANAGEMENT_ENABLED"] = "false"
	app, cleanup, err = wireApp(load())
	if err != nil {
		t.Fatal(err)
	}
	_, stop = startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer stop()
	httpCall("/v1/users/me/credentials:list", "{}", registered.Session.SessionToken, 404)
}
