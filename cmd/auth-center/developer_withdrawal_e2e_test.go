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
	app "github.com/TokenTeam/iwut-api-proto/gen/go/app_center/v1/application"
	ownerpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_owner_exit"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	devpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_application"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_withdrawal"
	emailpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	identitypb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/identity"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
	"time"
)

type ownerExitWireFixture struct {
	Env           map[string]string
	Conn, AppConn *grpc.ClientConn
	DB, AppDB     *m.Database
	Capture       *smtpcapture.Server
	ServiceKey    *rsa.PrivateKey
}

func newOwnerExitWireFixture(t *testing.T, overrides ...map[string]string) *ownerExitWireFixture {
	t.Helper()
	uri := os.Getenv(mongoIntegrationURIEnv)
	if uri == "" {
		t.Skip("run make test-mongo")
	}
	capture := smtpcapture.New(t, "implicit_tls")
	serviceKey, callers := testServiceCallerRegistry(t)
	encoded, _ := base64.StdEncoding.DecodeString(callers)
	var registry map[string]map[string]any
	if e := json.Unmarshal(encoded, &registry); e != nil {
		t.Fatal(e)
	}
	registry["gateway"] = map[string]any{"status": "ACTIVE", "keys": registry["app-center"]["keys"], "permissions": []string{"auth.identity.issue"}, "identityAudiences": []string{"iwut-auth-center", "iwut-app-center"}}
	registry["app-center"]["permissions"] = []string{"auth.scope-catalog.read", "auth.developer-status.read", "auth.system-principal.resolve", "auth.account-owner-exit.read"}
	encoded, _ = json.Marshal(registry)
	callers = base64.StdEncoding.EncodeToString(encoded)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "public.pem")
	catalog := filepath.Join(dir, "catalog.json")
	ca := filepath.Join(dir, "smtp-ca.pem")
	for path, data := range map[string][]byte{keyFile: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), catalog: []byte(`{"definitions":[]}`), ca: capture.CAPEM} {
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	keys, _ := json.Marshal(map[string]string{"identity-k1": keyFile})
	dbName := "uc024_wire_" + uuid.NewString()
	env := map[string]string{config.UserEndpointsEnabledEnv: "true", config.IdentityIssuanceEnabledEnv: "true", config.MongoURIEnv: uri, config.MongoDatabaseEnv: dbName, config.ServiceCallersEnv: callers, config.HTTPAddrEnv: reserveAddress(t), config.GRPCAddrEnv: reserveAddress(t), "AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h", "AUTH_ASSOC_KEY_VERSION": "v1", "AUTH_ASSOC_ENCRYPT_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "AUTH_ASSOC_LOOKUP_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "AUTH_PROFILE_CATALOG_FILE": catalog, "AUTH_USER_IDENTITY_ISSUER": "identity-test", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keys), "AUTH_USER_IDENTITY_SIGNING_KID": "identity-k1", "AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), "AUTH_EMAIL_BINDING_ENABLED": "true", "AUTH_EMAIL_BINDING_HMAC_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), "AUTH_EMAIL_LOGIN_ENABLED": "true", "AUTH_EMAIL_LOGIN_CODE_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "AUTH_SMTP_ADDR": capture.Address, "AUTH_SMTP_FROM": "auth@example.test", "AUTH_SMTP_TLS_MODE": "implicit_tls", "AUTH_SMTP_CA_FILE": ca, "AUTH_DEVELOPER_APPLICATION_ENABLED": "true", "AUTH_EMAIL_RECOVERY_READY": "true", "AUTH_DEVELOPER_ACCOUNT_PER_MINUTE": "1000", "AUTH_DEVELOPER_SOURCE_PER_MINUTE": "1000", "AUTH_DEVELOPER_GLOBAL_PER_MINUTE": "10000"}
	env["AUTH_DEVELOPER_MANAGEMENT_ENDPOINTS_ENABLED"] = "true"
	appGRPC := reserveAddress(t)
	serviceFile := filepath.Join(dir, "service.pem")
	if e := os.WriteFile(serviceFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serviceKey)}), 0600); e != nil {
		t.Fatal(e)
	}
	ownerConfig, _ := json.Marshal(config.OwnerExit{AppTarget: appGRPC, AppPlaintextLoopback: true, ServiceKeyID: "auth-service", ServiceKeyFile: serviceFile, AppServiceID: "app-center"})
	ownerFile := filepath.Join(dir, "owner.json")
	if e := os.WriteFile(ownerFile, ownerConfig, 0600); e != nil {
		t.Fatal(e)
	}
	env["AUTH_OWNER_EXIT_CONFIG_FILE"] = ownerFile
	env["AUTH_DEVELOPER_WITHDRAWAL_ENABLED"] = "true"
	env["AUTH_DEVELOPER_WITHDRAWAL_WRITE_PER_MINUTE"] = "1000"
	for _, override := range overrides {
		for k, v := range override {
			env[k] = v
		}
	}
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
	db := dbClient.Database(dbName)
	t.Cleanup(func() { db.Drop(context.Background()); dbClient.Disconnect(context.Background()) })
	app, cleanup, e := wireApp(load())
	if e != nil {
		t.Fatal(e)
	}
	conn, stop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	t.Cleanup(stop)
	publicDER, _ := x509.MarshalPKIXPublicKey(&serviceKey.PublicKey)
	appRegistry, _ := json.Marshal(map[string]any{"iwut-auth-center": map[string]any{"status": "ACTIVE", "keys": map[string]any{"auth-service": map[string]string{"publicKeyPemB64": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))}}, "permissions": []string{"app.account-owner-exit.prepare", "app.account-owner-exit.finish", "app.account-owner-exit.read", "app.oauth.client.read", "app.oauth.client.verify", "app.oauth.runtime.resolve", "app.oauth.context.resolve", "app.oauth.redirects.read"}}})
	appConn, _, appDB := startActualApp(t, uri, keyFile, env[config.GRPCAddrEnv], serviceKey, map[string]string{"APP_CENTER_GRPC_ADDR": appGRPC, "APP_CENTER_ACCOUNT_OWNER_EXIT_ENABLED": "true", "APP_CENTER_SERVICE_CALLERS_B64": base64.StdEncoding.EncodeToString(appRegistry)})
	return &ownerExitWireFixture{Env: env, Conn: conn, AppConn: appConn, DB: db, AppDB: appDB, Capture: capture, ServiceKey: serviceKey}
}
func (f *ownerExitWireFixture) RegisterDeveloper(t *testing.T, handle string) *authpb.UserRegistrationResult {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	association := make([]byte, 32)
	_, _ = rand.Read(association)
	user, _ := registerUser(t, authpb.NewAuthenticationServiceClient(f.Conn), key, association)
	ctx := sessionCallContext(t.Context(), user.Session.SessionToken)
	zero := int64(0)
	email := emailpb.NewEmailBindingServiceClient(f.Conn)
	challenge, e := email.BeginSetEmail(ctx, &emailpb.BeginSetEmailRequest{RequestId: uuid.NewString(), Email: handle + "@example.test", Intent: &emailpb.BeginSetEmailRequest_Binding{Binding: &emailpb.BindEmailIntent{ExpectedRevision: &zero}}})
	if e != nil {
		t.Fatal(e)
	}
	mail := f.Capture.Next(t)
	matches := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(mail.Body)
	if len(matches) != 2 {
		t.Fatal("missing email code")
	}
	if _, e = email.CompleteSetEmail(ctx, &emailpb.CompleteSetEmailRequest{OperationId: challenge.OperationId, Code: matches[1]}); e != nil {
		t.Fatal(e)
	}
	if _, e = devpb.NewDeveloperApplicationServiceClient(f.Conn).ApplyForDeveloper(ctx, &devpb.ApplyForDeveloperRequest{DeveloperHandle: handle}); e != nil {
		t.Fatal(e)
	}
	return user
}
func (f *ownerExitWireFixture) Issue(t *testing.T, u *authpb.UserRegistrationResult, audience string) string {
	t.Helper()
	ctx := metadata.AppendToOutgoingContext(serviceCallContext(t, t.Context(), f.ServiceKey, "gateway", "app-center-2026-01", "iwut-auth-center"), "x-iwut-session", u.Session.SessionToken)
	r, e := identitypb.NewUserIdentityServiceClient(f.Conn).IssueUserIdentityFromSession(ctx, &identitypb.IssueUserIdentityFromSessionRequest{Audience: audience})
	if e != nil {
		t.Fatal(e)
	}
	return r.IdentityJws
}
func (f *ownerExitWireFixture) HTTP(t *testing.T, u *authpb.UserRegistrationResult, path, body string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), "POST", "http://"+f.Env[config.HTTPAddrEnv]+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-iwut-session", u.Session.SessionToken)
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("cache control absent")
	}
	return resp.StatusCode, data
}
func TestDeveloperWithdrawalE2EActualApp(t *testing.T) {
	f := newOwnerExitWireFixture(t)
	user := f.RegisterDeveloper(t, "withdrawer")
	ctx := sessionCallContext(t.Context(), user.Session.SessionToken)
	client := pb.NewDeveloperWithdrawalServiceClient(f.Conn)
	oldToken := f.Issue(t, user, "iwut-app-center")
	appCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", oldToken))
	application := app.NewApplicationClient(f.AppConn)
	first, e := client.PrepareDeveloperWithdrawal(ctx, &pb.PrepareDeveloperWithdrawalRequest{RequestId: uuid.NewString(), ExpectedDeveloperRevision: 1})
	if e != nil || first.State != "READY" {
		t.Fatal(first, e)
	}
	if _, e = application.CreateApplication(appCtx, &app.CreateApplicationRequest{Name: "Forbidden_Prepared"}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("prepared barrier failed wrong reason", e)
	}
	if _, e = client.CancelDeveloperWithdrawal(ctx, &pb.CancelDeveloperWithdrawalRequest{OperationId: first.OperationId}); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var op bson.M
		e = f.DB.Collection(mongo.OwnerExitCollection).FindOne(t.Context(), bson.M{"operationId": first.OperationId}).Decode(&op)
		if e == nil && op["appAcknowledged"] == true {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancel not acknowledged", op, e)
		}
		time.Sleep(30 * time.Millisecond)
	}
	second, e := client.PrepareDeveloperWithdrawal(ctx, &pb.PrepareDeveloperWithdrawalRequest{RequestId: uuid.NewString(), ExpectedDeveloperRevision: 1})
	if e != nil || second.State != "READY" {
		t.Fatal(second, e)
	}
	for _, body := range []string{`{"operationId":"` + second.OperationId + `","unknown":true}`, `{"operationId":"` + second.OperationId + `","operation_id":"other"}`} {
		if code, data := f.HTTP(t, user, "/v1/users/me/developer-withdrawal:get", body); code != 400 {
			t.Fatal(code, string(data))
		}
	}
	if code, data := f.HTTP(t, user, "/v1/users/me/developer-withdrawal:confirm", `{"operationId":"`+second.OperationId+`","confirmation":"WITHDRAW_DEVELOPER"}`); code != 200 || !bytes.Contains(data, []byte("COMPLETED")) {
		t.Fatal(code, string(data))
	}
	completed, e := client.ConfirmDeveloperWithdrawal(ctx, &pb.ConfirmDeveloperWithdrawalRequest{OperationId: second.OperationId, Confirmation: "WITHDRAW_DEVELOPER"})
	if e != nil || completed.DeveloperStatus != "WITHDRAWN" || completed.DeveloperRevision != 2 {
		t.Fatal(completed, e)
	}
	if _, e = application.CreateApplication(appCtx, &app.CreateApplicationRequest{Name: "Forbidden_Completed"}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("withdrawn barrier failed wrong reason", e)
	}
	if got := identityPayload(t, f.Issue(t, user, "iwut-app-center"))["developer_status"]; got != "WITHDRAWN" {
		t.Fatal(got)
	}
	if _, e = devpb.NewDeveloperApplicationServiceClient(f.Conn).ApplyForDeveloper(ctx, &devpb.ApplyForDeveloperRequest{DeveloperHandle: "withdrawer"}); status.Code(e) != codes.PermissionDenied {
		t.Fatal("withdrawn reapplied", e)
	}
	decision := ownerpb.NewAccountOwnerExitDecisionServiceClient(f.Conn)
	request := &ownerpb.GetAccountOwnerExitDecisionRequest{AuthId: user.AuthId, OperationId: second.OperationId}
	if _, e = decision.GetAccountOwnerExitDecision(t.Context(), request); status.Code(e) != codes.Unauthenticated {
		t.Fatal(e)
	}
	serviceCtx := serviceCallContext(t, t.Context(), f.ServiceKey, "app-center", "app-center-2026-01", "iwut-auth-center")
	result, e := decision.GetAccountOwnerExitDecision(serviceCtx, request)
	if e != nil || result.Decision != ownerpb.Decision_DECISION_COMMITTED {
		t.Fatal(result, e)
	}
	owner := f.RegisterDeveloper(t, "withapps")
	ownerCtx := sessionCallContext(t.Context(), owner.Session.SessionToken)
	ownerAppCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", f.Issue(t, owner, "iwut-app-center")))
	if _, e := application.CreateApplication(ownerAppCtx, &app.CreateApplicationRequest{Name: "Existing_Owned_Application"}); e != nil {
		t.Fatal(e)
	}
	blocked, e := client.PrepareDeveloperWithdrawal(ownerCtx, &pb.PrepareDeveloperWithdrawalRequest{RequestId: uuid.NewString(), ExpectedDeveloperRevision: 1})
	if e != nil || blocked.State != "BLOCKED" || blocked.Blocker != "OWNED_APPLICATIONS" {
		t.Fatal(blocked, e)
	}
	if _, e = client.GetDeveloperWithdrawal(ownerCtx, &pb.GetDeveloperWithdrawalRequest{OperationId: second.OperationId}); status.Code(e) != codes.NotFound {
		t.Fatal("foreign operation disclosed", e)
	}
	if _, e = client.GetDeveloperWithdrawal(t.Context(), &pb.GetDeveloperWithdrawalRequest{OperationId: second.OperationId}); status.Code(e) != codes.Unauthenticated {
		t.Fatal(e)
	}

}
