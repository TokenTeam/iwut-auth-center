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
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	loginpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_login"
	accountpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"io"
	mongo "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/testutil/smtpcapture"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestE2E_EmailLogin_ProductionWireTLS(t *testing.T) {
	uri := os.Getenv(mongoIntegrationURIEnv)
	if uri == "" {
		t.Skip("run make test-mongo")
	}
	capture := smtpcapture.New(t, "implicit_tls")
	_, callers := testServiceCallerRegistry(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "identity.pem")
	catalog := filepath.Join(dir, "catalog.json")
	ca := filepath.Join(dir, "smtp-ca.pem")
	for path, data := range map[string][]byte{keyFile: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), catalog: []byte(`{"definitions":[]}`), ca: capture.CAPEM} {
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	keys, _ := json.Marshal(map[string]string{"test": keyFile})
	dbName := "uc012_wire_" + uuid.NewString()
	env := map[string]string{config.UserEndpointsEnabledEnv: "true", config.MongoURIEnv: uri, config.MongoDatabaseEnv: dbName, config.ServiceCallersEnv: callers, config.HTTPAddrEnv: reserveAddress(t), config.GRPCAddrEnv: reserveAddress(t), "AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h", "AUTH_ASSOC_KEY_VERSION": "v1", "AUTH_ASSOC_ENCRYPT_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "AUTH_ASSOC_LOOKUP_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "AUTH_PROFILE_CATALOG_FILE": catalog, "AUTH_USER_IDENTITY_ISSUER": "test", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keys), "AUTH_EMAIL_BINDING_ENABLED": "true", "AUTH_EMAIL_BINDING_HMAC_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), "AUTH_SMTP_ADDR": capture.Address, "AUTH_SMTP_FROM": "auth@example.test", "AUTH_SMTP_TLS_MODE": "implicit_tls", "AUTH_SMTP_CA_FILE": ca}
	enableEmailRegistrationFixture(t, env, capture)
	load := func() config.Config {
		c, e := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	dbClient, e := mongo.NewClient(uri)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		dbClient.Database(dbName).Drop(context.Background())
		dbClient.Disconnect(context.Background())
	})
	env["AUTH_EMAIL_LOGIN_ENABLED"] = "true"
	env["AUTH_EMAIL_LOGIN_CODE_KEY"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	app, cleanup, e := wireApp(load())
	if e != nil {
		t.Fatal(e)
	}
	conn, stop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer stop()
	emailClient := pb.NewEmailBindingServiceClient(conn)
	client := loginpb.NewEmailLoginServiceClient(conn)
	authClient := authpb.NewAuthenticationServiceClient(conn)
	base := "http://" + env[config.HTTPAddrEnv]
	httpTransport, e := khttp.NewClient(t.Context(), khttp.WithEndpoint(base))
	if e != nil {
		t.Fatal(e)
	}
	defer httpTransport.Close()
	httpClient := loginpb.NewEmailLoginServiceHTTPClient(httpTransport)
	nextCode := func() string {
		message := capture.Next(t)
		matches := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(message.Body)
		if len(matches) != 2 {
			t.Fatal("missing SMTP code")
		}
		return matches[1]
	}
	oldDevice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	accountClient := accountpb.NewEmailAccountServiceClient(conn)
	registered, e := accountClient.BeginEmailRegistration(t.Context(), &accountpb.BeginEmailRegistrationRequest{RequestId: uuid.NewString(), Email: "login@example.test", CredentialProposal: &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: elliptic.Marshal(elliptic.P256(), oldDevice.X, oldDevice.Y)}})
	if e != nil {
		t.Fatal(e)
	}
	activated, e := accountClient.CompleteEmailRegistration(t.Context(), &accountpb.CompleteEmailRegistrationRequest{OperationId: registered.OperationId, Code: nextCode(), Password: "a long fixture password 123", Proof: &authpb.CredentialProof{Signature: signDevice(t, oldDevice, registered.SigningPayload)}})
	if e != nil {
		t.Fatal(e)
	}
	device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	request := &loginpb.BeginEmailLoginRequest{RequestId: uuid.NewString(), Email: " LOGIN@EXAMPLE.TEST ", CredentialProposal: &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: elliptic.Marshal(elliptic.P256(), device.X, device.Y)}}
	for _, values := range [][]string{{""}, {"bad"}, {activated.RegistrationResult.Session.SessionToken}, {"a", "b"}} {
		ctx := metadata.NewOutgoingContext(t.Context(), metadata.MD{"x-iwut-session": values})
		if _, e = client.BeginEmailLogin(ctx, request); status.Code(e) != codes.InvalidArgument {
			t.Fatalf("supplied header accepted: %v", e)
		}
	}
	if _, e = client.BeginEmailLogin(t.Context(), request); status.Code(e) != codes.ResourceExhausted {
		t.Fatalf("cross-purpose mail quota bypassed: %v", e)
	}
	db := dbClient.Database(dbName)
	if _, e = db.Collection(mongo.EmailQuotaCollection).DeleteMany(t.Context(), bson.M{}); e != nil {
		t.Fatal(e)
	}
	challenge, e := httpClient.BeginEmailLogin(t.Context(), request)
	if e != nil {
		t.Fatal(e)
	}
	code := nextCode()
	if challenge.ProtocolVersion != "iwut-email-login-v1" || len(challenge.Challenge) != 32 {
		t.Fatal("invalid challenge")
	}
	if retry, e := client.BeginEmailLogin(t.Context(), request); e != nil || retry.OperationId != challenge.OperationId {
		t.Fatal("HTTP/gRPC idempotency", e)
	}
	send := func(path, body string, headers http.Header, want int, out proto.Message) {
		t.Helper()
		r, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
		r.Header = headers.Clone()
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		r.Header.Set("Content-Type", "application/json")
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("%s: got %d want %d: %s", path, response.StatusCode, want, data)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("missing no-store")
		}
		if out != nil {
			if e = protojson.Unmarshal(data, out); e != nil {
				t.Fatal(e)
			}
		}
	}
	for _, value := range []string{"", "bad", activated.RegistrationResult.Session.SessionToken} {
		send("/v1/email-logins", `{}`, http.Header{"X-Iwut-Session": {value}}, 400, nil)
	}
	for _, bad := range []string{`{"requestId":"a","request_id":"b"}`, `{"unknown":"private"}`, `{"credentialProposal":null}`, `{"email":"x","email":"y"}`} {
		send("/v1/email-logins", bad, nil, 400, nil)
	}
	send("/v1/email-logins", strings.Repeat(" ", 16*1024+1), nil, 413, nil)
	send("/v1/email-logins?email=private", `{}`, nil, 400, nil)
	signature := signDevice(t, device, challenge.SigningPayload)
	for _, values := range [][]string{{""}, {activated.RegistrationResult.Session.SessionToken}, {"a", "b"}} {
		ctx := metadata.NewOutgoingContext(t.Context(), metadata.MD{"x-iwut-session": values})
		if _, e = client.CompleteEmailLogin(ctx, &loginpb.CompleteEmailLoginRequest{OperationId: challenge.OperationId, Code: code, Proof: &authpb.CredentialProof{Signature: signature}}); status.Code(e) != codes.InvalidArgument {
			t.Fatal("complete accepted header", e)
		}
	}
	var result loginpb.EmailLoginResult
	body, _ := protojson.Marshal(&loginpb.CompleteEmailLoginRequest{OperationId: uuid.NewString(), Code: code, Proof: &authpb.CredentialProof{Signature: signature}})
	send("/v1/email-logins/"+challenge.OperationId+"/completion", string(body), nil, 201, &result)
	if result.AuthId != activated.RegistrationResult.AuthId || result.CredentialId != result.Session.CredentialId || result.Session.AuthId != result.AuthId {
		t.Fatal("wrong account/session")
	}
	if _, e = client.CompleteEmailLogin(t.Context(), &loginpb.CompleteEmailLoginRequest{OperationId: challenge.OperationId, Code: code, Proof: &authpb.CredentialProof{Signature: signature}}); status.Code(e) != codes.AlreadyExists {
		t.Fatal("replay", e)
	}
	if _, e = emailClient.GetOwnEmailBinding(sessionCallContext(t.Context(), result.Session.SessionToken), &pb.GetOwnEmailBindingRequest{}); e != nil {
		t.Fatal("email Session in UC011", e)
	}
	// Lost email-login response can recover through the existing device-only protocol.
	deviceChallenge, e := authClient.BeginDeviceLogin(t.Context(), &authpb.BeginDeviceLoginRequest{CredentialLocator: &authpb.BeginDeviceLoginRequest_CredentialId{CredentialId: result.CredentialId}})
	if e != nil {
		t.Fatal(e)
	}
	deviceSession, e := authClient.CompleteDeviceLogin(t.Context(), &authpb.CompleteDeviceLoginRequest{OperationId: deviceChallenge.OperationId, Proof: &authpb.CredentialProof{Signature: signDevice(t, device, deviceChallenge.SigningPayload)}})
	if e != nil || deviceSession.AuthId != result.AuthId {
		t.Fatal("UC007 recovery", e)
	}
	if _, e = authClient.RevokeCurrentSession(sessionCallContext(t.Context(), result.Session.SessionToken), &authpb.RevokeCurrentSessionRequest{}); e != nil {
		t.Fatal("UC008 email Session", e)
	}
	stop()
	// A login-only deployment needs the common SMTP and directory, but no binding key/routes.
	env["AUTH_EMAIL_BINDING_ENABLED"] = "false"
	env["AUTH_PASSWORD_ENABLED"] = "false"
	delete(env, "AUTH_EMAIL_BINDING_HMAC_KEY")
	env[config.HTTPAddrEnv] = reserveAddress(t)
	env[config.GRPCAddrEnv] = reserveAddress(t)
	app, cleanup, e = wireApp(load())
	if e != nil {
		t.Fatal("login-only composition", e)
	}
	conn, stop2 := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer stop2()
	client = loginpb.NewEmailLoginServiceClient(conn)
	if _, e = pb.NewEmailBindingServiceClient(conn).GetOwnEmailBinding(t.Context(), &pb.GetOwnEmailBindingRequest{}); status.Code(e) != codes.Unimplemented {
		t.Fatal("binding not disabled", e)
	}
	unknownKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	unknown, e := client.BeginEmailLogin(t.Context(), &loginpb.BeginEmailLoginRequest{RequestId: uuid.NewString(), Email: "unknown@example.test", CredentialProposal: &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: elliptic.Marshal(elliptic.P256(), unknownKey.X, unknownKey.Y)}})
	if e != nil {
		t.Fatal(e)
	}
	unknownCode := nextCode()
	if _, e = client.CompleteEmailLogin(t.Context(), &loginpb.CompleteEmailLoginRequest{OperationId: unknown.OperationId, Code: unknownCode, Proof: &authpb.CredentialProof{Signature: signDevice(t, unknownKey, unknown.SigningPayload)}}); status.Code(e) != codes.Unauthenticated {
		t.Fatal("unknown mailbox authenticated", e)
	}
	count, e := db.Collection(mongo.PrincipalCollection).CountDocuments(t.Context(), bson.M{"principalType": "USER"})
	if e != nil || count != 1 {
		t.Fatal("unknown email registered user", e)
	}
	stop2()
	env["AUTH_EMAIL_LOGIN_ENABLED"] = "false"
	delete(env, "AUTH_EMAIL_LOGIN_CODE_KEY")
	env[config.HTTPAddrEnv] = reserveAddress(t)
	env[config.GRPCAddrEnv] = reserveAddress(t)
	app, cleanup, e = wireApp(load())
	if e != nil {
		t.Fatal(e)
	}
	conn, stop3 := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer stop3()
	if _, e = loginpb.NewEmailLoginServiceClient(conn).BeginEmailLogin(t.Context(), request); status.Code(e) != codes.Unimplemented {
		t.Fatal("disabled login RPC", e)
	}
	response, e := http.Post("http://"+env[config.HTTPAddrEnv]+"/v1/email-logins", "application/json", strings.NewReader(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("disabled login route remains registered")
	}

}
