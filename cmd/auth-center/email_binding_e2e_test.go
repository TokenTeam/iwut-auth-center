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
	oldpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/google/uuid"
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

func TestE2E_EmailBinding_ProductionWireTLS(t *testing.T) {
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
	dbName := "uc011_wire_" + uuid.NewString()
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
	app, cleanup, e := wireApp(load())
	if e != nil {
		t.Fatal(e)
	}
	connection, stop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer stop()
	client := pb.NewEmailAccountServiceClient(connection)
	base := "http://" + env[config.HTTPAddrEnv]
	httpTransport, e := khttp.NewClient(t.Context(), khttp.WithEndpoint(base))
	if e != nil {
		t.Fatal(e)
	}
	defer httpTransport.Close()
	httpClient := pb.NewEmailAccountServiceHTTPClient(httpTransport)
	device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	request := &pb.BeginEmailRegistrationRequest{RequestId: uuid.NewString(), Email: " User+TAG@EXAMPLE.TEST ", CredentialProposal: &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: elliptic.Marshal(elliptic.P256(), device.X, device.Y)}}
	// Invalid provided carriers must be rejected before any anonymous fallback.
	for _, values := range [][]string{{""}, {" "}, {"bad"}, {strings.Repeat("A", 43)}, {"a", "b"}} {
		ctx := metadata.NewOutgoingContext(t.Context(), metadata.MD{"x-iwut-session": values})
		if _, e = client.BeginEmailRegistration(ctx, request); status.Code(e) != codes.Unauthenticated {
			t.Fatalf("invalid carrier: %v", e)
		}
	}
	started, e := httpClient.BeginEmailRegistration(t.Context(), request)
	if e != nil {
		t.Fatal(e)
	}
	if started.ProtocolVersion != "iwut-email-registration-v3" {
		t.Fatal("incorrect registration response")
	}
	nextCode := func() string {
		m := capture.Next(t)
		matches := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(m.Body)
		if len(matches) != 2 {
			t.Fatal("SMTP code missing")
		}
		return matches[1]
	}
	code := nextCode()
	// Reserved student-association input is rejected in both native Proto and
	// strict JSON, never silently dropped into a new registration.
	deprecated := proto.Clone(request).(*pb.BeginEmailRegistrationRequest)
	deprecated.CredentialProposal.ProtoReflect().SetUnknown([]byte{0x12, 0})
	if _, e := client.BeginEmailRegistration(t.Context(), deprecated); status.Code(e) != codes.InvalidArgument {
		t.Fatal("retired protobuf field accepted", e)
	}
	oldJSON, _ := protojson.Marshal(request)
	oldJSON = bytes.Replace(oldJSON, []byte(`"credentialProposal":{`), []byte(`"credentialProposal":{"association":{},`), 1)
	oldRequest, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/v3/email-registrations", bytes.NewReader(oldJSON))
	oldRequest.Header.Set("Content-Type", "application/json")
	oldResponse, e := http.DefaultClient.Do(oldRequest)
	if e != nil {
		t.Fatal(e)
	}
	oldResponse.Body.Close()
	if oldResponse.StatusCode != 400 {
		t.Fatal("retired JSON field accepted", oldResponse.StatusCode)
	}
	if again, e := client.BeginEmailRegistration(t.Context(), request); e != nil || again.OperationId != started.OperationId {
		t.Fatalf("cross-transport idempotency: %v", e)
	}
	completion := &pb.CompleteEmailRegistrationRequest{OperationId: started.OperationId, Code: code, Password: "a long fixture password 123", Proof: &authpb.CredentialProof{Signature: signDevice(t, device, started.SigningPayload)}}
	activated, e := client.CompleteEmailRegistration(t.Context(), completion)
	if e != nil {
		t.Fatal(e)
	}
	if activated.RegistrationResult.GetSession().GetSessionToken() == "" {
		t.Fatal("missing first session")
	}
	token := activated.RegistrationResult.Session.SessionToken
	sessionCtx := sessionCallContext(t.Context(), token)
	if _, e = client.CompleteEmailRegistration(sessionCtx, completion); status.Code(e) != codes.Unauthenticated {
		t.Fatalf("REGISTER switched mode: %v", e)
	}
	if _, e = client.CompleteEmailRegistration(t.Context(), completion); status.Code(e) != codes.AlreadyExists {
		t.Fatalf("token replay: %v", e)
	}
	own, e := client.GetOwnEmails(sessionCtx, &pb.GetOwnEmailsRequest{})
	if e != nil || own.DirectoryRevision != 1 || own.LoginRoleRevision != 1 || len(own.Emails) != 1 || own.Emails[0].Email != "user+tag@example.test" {
		t.Fatalf("query: %v %v", own, e)
	}
	if _, e = client.GetOwnEmails(t.Context(), &pb.GetOwnEmailsRequest{}); status.Code(e) != codes.Unauthenticated {
		t.Fatal("anonymous query accepted")
	}
	pending, e := client.BeginAddOwnEmail(sessionCtx, &pb.BeginAddOwnEmailRequest{RequestId: uuid.NewString(), Email: "replace@example.test", ExpectedDirectoryRevision: 1})
	if e != nil {
		t.Fatal(e)
	}
	bindCode := nextCode()

	send := func(method, path, body string, headers http.Header, want int, out proto.Message) {
		t.Helper()
		r, e := http.NewRequest(method, base+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
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
			t.Fatalf("%s %s: status %d body %s", method, path, response.StatusCode, data)
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
	headers := http.Header{"X-Iwut-Session": {token}}
	var bound pb.OwnEmailAdded
	send("POST", "/v3/users/me/email-verifications:complete", `{"operationId":"`+pending.OperationId+`","code":"`+bindCode+`"}`, headers, 200, &bound)
	if bound.Emails.DirectoryRevision != 2 || bound.Emails.LoginRoleRevision != 1 || len(bound.Emails.Emails) != 2 {
		t.Fatal("ADD changed role")
	}
	send("GET", "/v3/users/me/emails", "", headers, 200, nil)
	for _, v := range []string{"", "bad", token + "," + token} {
		send("GET", "/v3/users/me/emails", "", http.Header{"X-Iwut-Session": {v}}, 401, nil)
	}
	send("GET", "/v3/users/me/emails", "", http.Header{"X-Iwut-Session": {token, token}}, 401, nil)
	for _, bad := range []string{`{"requestId":"a","request_id":"b"}`, `{"credentialProposal":{},"email":null,"requestId":"a"}`, `{"unknown":"private-value"}`, `{"requestId":"a","email":"a@example.test","credentialProposal":{"protocolVersion":"iwut-device-v1","publicKey":null}}`} {
		send("POST", "/v3/email-registrations", bad, nil, 400, nil)
	}
	send("POST", "/v3/email-registrations", strings.Repeat(" ", 16*1024+1), nil, 413, nil)
	send("GET", "/v3/users/me/emails?email=secret", "", headers, 400, nil)
	var target string
	for _, b := range bound.Emails.Emails {
		if b.Email == "replace@example.test" {
			target = b.BindingId
		}
	}
	switchRequest := &pb.SwitchOwnLoginEmailRequest{RequestId: uuid.NewString(), TargetBindingId: target, CurrentPassword: "wrong fixture password", ExpectedDirectoryRevision: 2, ExpectedLoginRoleRevision: 1}
	if _, e = client.SwitchOwnLoginEmail(sessionCtx, switchRequest); status.Code(e) != codes.Unauthenticated {
		t.Fatal("switch without password", e)
	}
	switchRequest.CurrentPassword = "a long fixture password 123"
	switched, e := client.SwitchOwnLoginEmail(sessionCtx, switchRequest)
	if e != nil || switched.Emails.DirectoryRevision != 3 || switched.Emails.LoginRoleRevision != 2 {
		t.Fatal("switch", switched, e)
	}
	if _, e = client.GetOwnEmails(sessionCtx, &pb.GetOwnEmailsRequest{}); e != nil {
		t.Fatal("switch cleared Session", e)
	}
	if _, e = client.RemoveOwnEmail(sessionCtx, &pb.RemoveOwnEmailRequest{RequestId: uuid.NewString(), BindingId: target, ExpectedDirectoryRevision: 3}); status.Code(e) != codes.AlreadyExists {
		t.Fatal("removed primary", e)
	}
	oldClient := oldpb.NewEmailBindingServiceClient(connection)
	if _, e = oldClient.BeginSetEmail(t.Context(), &oldpb.BeginSetEmailRequest{}); status.Code(e) != codes.Unimplemented {
		t.Fatal("old registration bypass", e)
	}
	if _, e = oldClient.CompleteSetEmail(t.Context(), &oldpb.CompleteSetEmailRequest{}); status.Code(e) != codes.Unimplemented {
		t.Fatal("old completion bypass", e)
	}
	send("POST", "/v1/email-bindings", "{}", nil, 404, nil)
	projection, e := oldClient.GetOwnEmailBinding(sessionCtx, &oldpb.GetOwnEmailBindingRequest{})
	if e != nil || projection.ActiveEmail.Email != "replace@example.test" || projection.Revision != 2 || projection.Pending != nil {
		t.Fatal("read projection", projection, e)
	}
	// A valid Session paired with registration does not register another user.
	request.RequestId = uuid.NewString()
	if _, e = client.BeginEmailRegistration(sessionCtx, request); status.Code(e) != codes.Unauthenticated {
		t.Fatal("session registration accepted")
	}
	if _, e = authpb.NewAuthenticationServiceClient(connection).RevokeCurrentSession(sessionCtx, &authpb.RevokeCurrentSessionRequest{}); e != nil {
		t.Fatal(e)
	}
	if _, e = client.BeginEmailRegistration(sessionCtx, request); status.Code(e) != codes.Unauthenticated {
		t.Fatal("revoked session became anonymous")
	}
	stop()
	// SMTP accepts DATA but loses the acknowledgement after the Begin transaction
	// commits. Retrying the request recovers metadata without a second send.
	uncertain := smtpcapture.New(t, "lost_ack")
	uncertainCA := filepath.Join(dir, "uncertain-ca.pem")
	if e = os.WriteFile(uncertainCA, uncertain.CAPEM, 0600); e != nil {
		t.Fatal(e)
	}
	env["AUTH_SMTP_ADDR"] = uncertain.Address
	env["AUTH_SMTP_CA_FILE"] = uncertainCA
	env[config.HTTPAddrEnv] = reserveAddress(t)
	env[config.GRPCAddrEnv] = reserveAddress(t)
	app, cleanup, e = wireApp(load())
	if e != nil {
		t.Fatal(e)
	}
	uncertainConnection, uncertainStop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	uncertainClient := pb.NewEmailAccountServiceClient(uncertainConnection)
	newDevice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uncertainRequest := proto.Clone(request).(*pb.BeginEmailRegistrationRequest)
	uncertainRequest.RequestId = uuid.NewString()
	uncertainRequest.Email = "uncertain@example.test"
	uncertainRequest.CredentialProposal.PublicKey = elliptic.Marshal(elliptic.P256(), newDevice.X, newDevice.Y)
	if _, e = uncertainClient.BeginEmailRegistration(t.Context(), uncertainRequest); status.Code(e) != codes.Unavailable {
		t.Fatalf("lost SMTP acknowledgement: %v", e)
	}
	uncertainMessage := uncertain.Next(t)
	uncertainCode := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(uncertainMessage.Body)[1]
	recovered, e := uncertainClient.BeginEmailRegistration(t.Context(), uncertainRequest)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = uncertainClient.CompleteEmailRegistration(t.Context(), &pb.CompleteEmailRegistrationRequest{OperationId: recovered.OperationId, Code: uncertainCode, Password: "a long fixture password 123", Proof: &authpb.CredentialProof{Signature: signDevice(t, newDevice, recovered.SigningPayload)}}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-uncertain.Messages:
		t.Fatal("uncertain Begin redelivered")
	default:
	}
	uncertainStop()
	env["AUTH_EMAIL_BINDING_ENABLED"] = "false"
	env["AUTH_PASSWORD_ENABLED"] = "false"
	env[config.HTTPAddrEnv] = reserveAddress(t)
	env[config.GRPCAddrEnv] = reserveAddress(t)
	app, cleanup, e = wireApp(load())
	if e != nil {
		t.Fatal(e)
	}
	connection, disabledStop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer disabledStop()
	if _, e = pb.NewEmailAccountServiceClient(connection).GetOwnEmails(t.Context(), &pb.GetOwnEmailsRequest{}); status.Code(e) != codes.Unimplemented {
		t.Fatalf("disabled gRPC: %v", e)
	}
	resp, e := http.Get("http://" + env[config.HTTPAddrEnv] + "/v1/users/me/email-binding")
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("disabled HTTP route registered")
	}
	select {
	case <-capture.Messages:
		t.Fatal("idempotent Begin sent another email")
	default:
	}
}
