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
	apppb "github.com/TokenTeam/iwut-api-proto/gen/go/app_center/v1/application"
	reviewpb "github.com/TokenTeam/iwut-api-proto/gen/go/app_center/v1/application_review"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_application"
	statuspb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_status"
	emailpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	loginpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_login"
	identitypb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/identity"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	mongo "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/testutil/smtpcapture"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestE2E_DeveloperApplication_ProductionWireAndAppCenter(t *testing.T) {
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
	dbName := "uc013_wire_" + uuid.NewString()
	env := map[string]string{config.UserEndpointsEnabledEnv: "true", config.IdentityIssuanceEnabledEnv: "true", config.MongoURIEnv: uri, config.MongoDatabaseEnv: dbName, config.ServiceCallersEnv: callers, config.HTTPAddrEnv: reserveAddress(t), config.GRPCAddrEnv: reserveAddress(t), "AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h", "AUTH_ASSOC_KEY_VERSION": "v1", "AUTH_ASSOC_ENCRYPT_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "AUTH_ASSOC_LOOKUP_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "AUTH_PROFILE_CATALOG_FILE": catalog, "AUTH_USER_IDENTITY_ISSUER": "identity-test", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keys), "AUTH_USER_IDENTITY_SIGNING_KID": "identity-k1", "AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), "AUTH_EMAIL_BINDING_ENABLED": "true", "AUTH_EMAIL_BINDING_HMAC_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), "AUTH_EMAIL_LOGIN_ENABLED": "true", "AUTH_EMAIL_LOGIN_CODE_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "AUTH_SMTP_ADDR": capture.Address, "AUTH_SMTP_FROM": "auth@example.test", "AUTH_SMTP_TLS_MODE": "implicit_tls", "AUTH_SMTP_CA_FILE": ca, "AUTH_DEVELOPER_APPLICATION_ENABLED": "true", "AUTH_EMAIL_RECOVERY_READY": "true", "AUTH_DEVELOPER_ACCOUNT_PER_MINUTE": "1000", "AUTH_DEVELOPER_SOURCE_PER_MINUTE": "1000", "AUTH_DEVELOPER_GLOBAL_PER_MINUTE": "10000"}
	env["AUTH_DEVELOPER_MANAGEMENT_ENDPOINTS_ENABLED"] = "true"
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
	defer stop()
	client := pb.NewDeveloperApplicationServiceClient(conn)
	auth := authpb.NewAuthenticationServiceClient(conn)
	device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	user, _ := registerUser(t, auth, device, bytes.Repeat([]byte{9}, 32))
	ctx := sessionCallContext(t.Context(), user.Session.SessionToken)
	query, e := client.GetOwnDeveloperEligibility(ctx, &pb.GetOwnDeveloperEligibilityRequest{})
	if e != nil || query.DeveloperStatus != nil || query.ActivatedAtUnixMs != nil || query.DeveloperHandle != nil || query.CanApply || len(query.Blockers) != 1 || query.Blockers[0] != pb.DeveloperApplicationBlocker_DEVELOPER_APPLICATION_BLOCKER_EMAIL_REQUIRED {
		t.Fatal(query, e)
	}
	if _, e = client.ApplyForDeveloper(ctx, &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal(e)
	}
	base := "http://" + env[config.HTTPAddrEnv]
	rawHTTP := func(method, path, body string, headers http.Header) (int, http.Header, []byte) {
		t.Helper()
		r, e := http.NewRequestWithContext(t.Context(), method, base+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header = headers.Clone()
		r.Header.Set("Content-Type", "application/json")
		resp, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b, e := io.ReadAll(resp.Body)
		if e != nil {
			t.Fatal(e)
		}
		return resp.StatusCode, resp.Header, b
	}
	headers := http.Header{"X-Iwut-Session": []string{user.Session.SessionToken}}
	code, h, body := rawHTTP("POST", "/v1/users/me/developer-application", `{"developerHandle":"Alice"}`, headers)
	if code != 409 || !bytes.Contains(body, []byte("DEVELOPER_EMAIL_REQUIRED")) || h.Get("Cache-Control") != "no-store" {
		t.Fatal(code, string(body), h)
	}
	for _, values := range [][]string{nil, {""}, {"bad"}, {user.Session.SessionToken, user.Session.SessionToken}} {
		badctx := metadata.NewOutgoingContext(t.Context(), metadata.MD{"x-iwut-session": values})
		if _, e = client.ApplyForDeveloper(badctx, &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"}); status.Code(e) != codes.Unauthenticated {
			t.Fatal(values, e)
		}
	}
	for _, carrier := range []string{"authorization", "cookie", "x-iwut-identity"} {
		badctx := metadata.AppendToOutgoingContext(ctx, carrier, "not-a-session")
		if _, e = client.GetOwnDeveloperEligibility(badctx, &pb.GetOwnDeveloperEligibilityRequest{}); status.Code(e) != codes.Unauthenticated {
			t.Fatal(carrier, e)
		}
	}
	for _, payload := range []string{"", "null", "[]", `{"authId":"other"}`, `{"canApply":true}`, `{"requestId":"x"}`, `{"email":"x@example.test"}`, `{"developerHandle":"Alice","developer_handle":"Bob"}`} {
		code, _, body := rawHTTP("POST", "/v1/users/me/developer-application", payload, headers)
		if code != 400 || !bytes.Contains(body, []byte("INVALID_DEVELOPER_APPLICATION_REQUEST")) {
			t.Fatal(payload, code, string(body))
		}
	}
	for _, payload := range []string{`{}`, `{"developerHandle":null}`, `{"developerHandle":""}`, `{"developerHandle":"ab"}`, `{"developerHandle":" Alice"}`, `{"developerHandle":"Ａlice"}`, `{"developerHandle":"alice.name"}`, `{"developer_handle":"1abc"}`} {
		code, _, body := rawHTTP("POST", "/v1/users/me/developer-application", payload, headers)
		if code != 400 || !bytes.Contains(body, []byte("INVALID_DEVELOPER_HANDLE")) {
			t.Fatal(payload, code, string(body))
		}
	}
	for _, handle := range []string{"", "ab", " Alice", "Ａlice", "alice/name"} {
		if _, e = client.ApplyForDeveloper(ctx, &pb.ApplyForDeveloperRequest{DeveloperHandle: handle}); status.Code(e) != codes.InvalidArgument {
			t.Fatal(handle, e)
		}
	}
	code, _, body = rawHTTP("GET", "/v1/users/me/developer-eligibility?authId=other", "", headers)
	if code != 400 {
		t.Fatal(code, string(body))
	}
	code, _, body = rawHTTP("POST", "/v1/users/me/developer-application", strings.Repeat(" ", 16385), headers)
	if code != 413 || !bytes.Contains(body, []byte("DEVELOPER_APPLICATION_REQUEST_TOO_LARGE")) {
		t.Fatal(code, string(body))
	}
	unknown := &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"}
	unknown.ProtoReflect().SetUnknown([]byte{0x12, 1, 'x'})
	if _, e = client.ApplyForDeveloper(ctx, unknown); status.Code(e) != codes.InvalidArgument {
		t.Fatal(e)
	}
	unknown.ProtoReflect().SetUnknown(bytes.Repeat([]byte{0x10, 1}, 9000))
	if _, e = client.ApplyForDeveloper(ctx, unknown); status.Code(e) != codes.ResourceExhausted {
		t.Fatal(e)
	}
	if e = conn.Invoke(ctx, "/auth_center.v1.developer_application.DeveloperApplicationService/Unknown", &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"}, &pb.DeveloperApplicationResult{}); status.Code(e) != codes.Unimplemented {
		t.Fatal(e)
	}
	nextCode := func() string {
		m := capture.Next(t)
		matches := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(m.Body)
		if len(matches) != 2 {
			t.Fatal("no capture code")
		}
		return matches[1]
	}
	revision := int64(0)
	emailClient := emailpb.NewEmailBindingServiceClient(conn)
	challenge, e := emailClient.BeginSetEmail(ctx, &emailpb.BeginSetEmailRequest{RequestId: uuid.NewString(), Email: "developer@example.test", Intent: &emailpb.BeginSetEmailRequest_Binding{Binding: &emailpb.BindEmailIntent{ExpectedRevision: &revision}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = emailClient.CompleteSetEmail(ctx, &emailpb.CompleteSetEmailRequest{OperationId: challenge.OperationId, Code: nextCode()}); e != nil {
		t.Fatal(e)
	}
	query, e = client.GetOwnDeveloperEligibility(ctx, &pb.GetOwnDeveloperEligibilityRequest{})
	if e != nil || !query.CanApply || query.DeveloperStatus != nil {
		t.Fatal(query, e)
	}
	issuer := identitypb.NewUserIdentityServiceClient(conn)
	issue := func(audience string) string {
		t.Helper()
		ic := metadata.AppendToOutgoingContext(serviceCallContext(t, t.Context(), serviceKey, "gateway", "app-center-2026-01", "iwut-auth-center"), "x-iwut-session", user.Session.SessionToken)
		r, e := issuer.IssueUserIdentityFromSession(ic, &identitypb.IssueUserIdentityFromSessionRequest{Audience: audience})
		if e != nil {
			t.Fatal(e)
		}
		return r.IdentityJws
	}
	before := issue("iwut-app-center")
	// Recover a second device through the actual UC012 flow before applying.
	if _, e = db.Collection(mongo.EmailQuotaCollection).DeleteMany(t.Context(), bson.M{}); e != nil {
		t.Fatal(e)
	}
	loginDevice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	loginClient := loginpb.NewEmailLoginServiceClient(conn)
	loginChallenge, e := loginClient.BeginEmailLogin(t.Context(), &loginpb.BeginEmailLoginRequest{RequestId: uuid.NewString(), Email: "developer@example.test", CredentialProposal: &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: elliptic.Marshal(elliptic.P256(), loginDevice.X, loginDevice.Y)}})
	if e != nil {
		t.Fatal(e)
	}
	logged, e := loginClient.CompleteEmailLogin(t.Context(), &loginpb.CompleteEmailLoginRequest{OperationId: loginChallenge.OperationId, Code: nextCode(), Proof: &authpb.CredentialProof{Signature: signDevice(t, loginDevice, loginChallenge.SigningPayload)}})
	if e != nil {
		t.Fatal(e)
	}
	result, e := client.ApplyForDeveloper(sessionCallContext(t.Context(), logged.Session.SessionToken), &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"})
	if e != nil || result.DeveloperStatus != statuspb.DeveloperStatus_DEVELOPER_STATUS_APPROVED || result.GetActivatedAtUnixMs() <= 0 || result.DeveloperHandle != "alice" {
		t.Fatal(result, e)
	}
	repeat, e := client.ApplyForDeveloper(ctx, &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"})
	if e != nil || repeat.GetActivatedAtUnixMs() != result.GetActivatedAtUnixMs() {
		t.Fatal(repeat, e)
	}
	caseRetry, e := client.ApplyForDeveloper(ctx, &pb.ApplyForDeveloperRequest{DeveloperHandle: "ALICE"})
	if e != nil || caseRetry.DeveloperHandle != "alice" {
		t.Fatal(caseRetry, e)
	}
	code, _, body = rawHTTP("POST", "/v1/users/me/developer-application", `{"developerHandle":"OtherName"}`, headers)
	if code != 409 || !bytes.Contains(body, []byte("DEVELOPER_HANDLE_CHANGE_NOT_ALLOWED")) {
		t.Fatal(code, string(body))
	}
	httpTransport, e := khttp.NewClient(t.Context(), khttp.WithEndpoint(base))
	if e != nil {
		t.Fatal(e)
	}
	defer httpTransport.Close()
	httpClient := pb.NewDeveloperApplicationServiceHTTPClient(httpTransport)
	clientHeaders := headers.Clone()
	httpResult, e := httpClient.ApplyForDeveloper(t.Context(), &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"}, khttp.Header(&clientHeaders))
	if e != nil || httpResult.GetActivatedAtUnixMs() != result.GetActivatedAtUnixMs() || httpResult.DeveloperHandle != "alice" {
		t.Fatal(httpResult, e)
	}
	code, _, body = rawHTTP("GET", "/v1/users/me/developer-eligibility", "", headers)
	if code != 200 {
		t.Fatal(code, string(body))
	}
	var fields map[string]any
	if e = json.Unmarshal(body, &fields); e != nil {
		t.Fatal(e)
	}
	if fields["developerHandle"] != "alice" {
		t.Fatal(fields)
	}
	if _, ok := fields["activatedAtUnixMs"].(string); !ok {
		t.Fatal("int64 JSON presence", fields)
	}
	directory := statuspb.NewDeveloperStatusDirectoryClient(conn)
	statuses, e := directory.BatchGetDeveloperStatuses(serviceCallContext(t, t.Context(), serviceKey, "app-center", "app-center-2026-01", "iwut-auth-center"), &statuspb.BatchGetDeveloperStatusesRequest{AuthIds: []string{user.AuthId}})
	if e != nil || statuses.Entries[0].DeveloperStatus != statuspb.DeveloperStatus_DEVELOPER_STATUS_APPROVED {
		t.Fatal(statuses, e)
	}
	after := issue("iwut-app-center")
	if identityPayload(t, after)["developer_status"] != "APPROVED" || len(identityPayload(t, after)["permissions"].([]any)) != 0 || identityPayload(t, before)["developer_status"] != nil {
		t.Fatal("claims not current")
	}
	if identityPayload(t, issue("iwut-auth-center"))["developer_status"] != nil {
		t.Fatal("auth audience exposed developer status")
	}
	t.Run("actual App Center", func(t *testing.T) {
		developerActualAppFlow(t, uri, keyFile, env[config.GRPCAddrEnv], serviceKey, user.AuthId, issue)
	})
	managementIdentity := runDeveloperManagementFlow(t, env, conn, user, issue, keyFile, serviceKey)
	// Simulate an imported APPROVED principal without activation history, then
	// bind through the actual email flow and explicitly claim its first handle.
	legacyDevice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	legacy, _ := registerUser(t, auth, legacyDevice, bytes.Repeat([]byte{6}, 32))
	legacyCtx := sessionCallContext(t.Context(), legacy.Session.SessionToken)
	legacyEmail, e := emailClient.BeginSetEmail(legacyCtx, &emailpb.BeginSetEmailRequest{RequestId: uuid.NewString(), Email: "legacy@example.test", Intent: &emailpb.BeginSetEmailRequest_Binding{Binding: &emailpb.BindEmailIntent{ExpectedRevision: &revision}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = emailClient.CompleteSetEmail(legacyCtx, &emailpb.CompleteSetEmailRequest{OperationId: legacyEmail.OperationId, Code: nextCode()}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Collection(mongo.PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": legacy.AuthId}, bson.M{"$set": bson.M{"developerStatus": "APPROVED", "developerRevision": int64(1)}}); e != nil {
		t.Fatal(e)
	}
	legacyEligibility, e := client.GetOwnDeveloperEligibility(legacyCtx, &pb.GetOwnDeveloperEligibilityRequest{})
	if e != nil || !legacyEligibility.CanApply || legacyEligibility.DeveloperHandle != nil || legacyEligibility.ActivatedAtUnixMs != nil {
		t.Fatal(legacyEligibility, e)
	}
	legacyHeaders := http.Header{"X-Iwut-Session": []string{legacy.Session.SessionToken}}
	code, _, body = rawHTTP("POST", "/v1/users/me/developer-application", `{"developerHandle":"ALICE"}`, legacyHeaders)
	if code != 409 || !bytes.Contains(body, []byte("DEVELOPER_HANDLE_TAKEN")) || bytes.Contains(body, []byte(user.AuthId)) {
		t.Fatal(code, string(body))
	}
	legacyClaim, e := client.ApplyForDeveloper(legacyCtx, &pb.ApplyForDeveloperRequest{DeveloperHandle: "Legacy_Name"})
	if e != nil || legacyClaim.DeveloperHandle != "legacy_name" || legacyClaim.ActivatedAtUnixMs != nil {
		t.Fatal(legacyClaim, e)
	}
	legacyJSON, e := protojson.Marshal(legacyClaim)
	if e != nil || bytes.Contains(legacyJSON, []byte("activatedAtUnixMs")) {
		t.Fatal(string(legacyJSON), e)
	}
	if _, e = client.ApplyForDeveloper(ctx, &pb.ApplyForDeveloperRequest{}); status.Code(e) != codes.InvalidArgument {
		t.Fatal("existing handle bypassed required input", e)
	}

	stop()
	// Closing readiness and all UC012 capability keeps current APPROVED idempotent,
	// but blocks first application. Disabled registration is a separate gate.
	env[config.HTTPAddrEnv] = reserveAddress(t)
	env[config.GRPCAddrEnv] = reserveAddress(t)
	env["AUTH_EMAIL_LOGIN_ENABLED"] = "false"
	env["AUTH_EMAIL_RECOVERY_READY"] = "false"
	env["AUTH_DEVELOPER_ACCOUNT_PER_MINUTE"] = "2"
	closed, closedCleanup, e := wireApp(load())
	if e != nil {
		t.Fatal(e)
	}
	closedConn, closedStop := startUserApp(t, closed, closedCleanup, env[config.GRPCAddrEnv])
	defer closedStop()
	closedClient := pb.NewDeveloperApplicationServiceClient(closedConn)
	if r, e := closedClient.ApplyForDeveloper(ctx, &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"}); e != nil || r.GetActivatedAtUnixMs() != result.GetActivatedAtUnixMs() {
		t.Fatal(r, e)
	}
	if _, e = closedClient.GetOwnDeveloperEligibility(ctx, &pb.GetOwnDeveloperEligibilityRequest{}); e != nil {
		t.Fatal(e)
	}
	base = "http://" + env[config.HTTPAddrEnv]
	code, h, body = rawHTTP("POST", "/v1/users/me/developer-application", `{"developerHandle":"Alice"}`, headers)
	if code != 429 || h.Get("Retry-After") != "60" || !bytes.Contains(body, []byte("DEVELOPER_APPLICATION_RATE_LIMITED")) {
		t.Fatal(code, string(body), h)
	}
	runDeveloperManagementRecoveryClosed(t, closedConn, user.AuthId, managementIdentity)
	newDevice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ordinary, _ := registerUser(t, authpb.NewAuthenticationServiceClient(closedConn), newDevice, bytes.Repeat([]byte{8}, 32))
	ordinaryCtx := sessionCallContext(t.Context(), ordinary.Session.SessionToken)
	blocked, e := closedClient.GetOwnDeveloperEligibility(ordinaryCtx, &pb.GetOwnDeveloperEligibilityRequest{})
	if e != nil || len(blocked.Blockers) != 2 || blocked.Blockers[0] != pb.DeveloperApplicationBlocker_DEVELOPER_APPLICATION_BLOCKER_EMAIL_REQUIRED || blocked.Blockers[1] != pb.DeveloperApplicationBlocker_DEVELOPER_APPLICATION_BLOCKER_EMAIL_LOGIN_UNAVAILABLE {
		t.Fatal(blocked, e)
	}
	// Historical APPROVED stays nullable and does not manufacture activation history.
	if _, e = db.Collection(mongo.PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": ordinary.AuthId}, bson.M{"$set": bson.M{"developerStatus": "APPROVED", "developerRevision": int64(1)}}); e != nil {
		t.Fatal(e)
	}
	historical, e := closedClient.GetOwnDeveloperEligibility(ordinaryCtx, &pb.GetOwnDeveloperEligibilityRequest{})
	if e != nil || historical.ActivatedAtUnixMs != nil {
		t.Fatal(historical, e)
	}
	b, e := protojson.Marshal(historical)
	if e != nil || bytes.Contains(b, []byte("activatedAtUnixMs")) {
		t.Fatal(string(b), e)
	}
	closedStop()
	delete(env, "AUTH_DEVELOPER_APPLICATION_ENABLED")
	env[config.HTTPAddrEnv] = reserveAddress(t)
	env[config.GRPCAddrEnv] = reserveAddress(t)
	disabled, disabledCleanup, e := wireApp(load())
	if e != nil {
		t.Fatal(e)
	}
	disabledConn, disabledStop := startUserApp(t, disabled, disabledCleanup, env[config.GRPCAddrEnv])
	defer disabledStop()
	if _, e = pb.NewDeveloperApplicationServiceClient(disabledConn).ApplyForDeveloper(ctx, &pb.ApplyForDeveloperRequest{DeveloperHandle: "Alice"}); status.Code(e) != codes.Unimplemented {
		t.Fatal(e)
	}
	resp, e := http.Get("http://" + env[config.HTTPAddrEnv] + "/v1/users/me/developer-eligibility")
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
}

// Build and run the actual sibling App Center, including its production Wire
// composition and Mongo migrations. No App source files or stubs are installed.
func startActualApp(t *testing.T, uri, keyFile, authTarget string, serviceKey *rsa.PrivateKey, overrides ...map[string]string) (*grpc.ClientConn, string, *drivermongo.Database) {
	source := os.Getenv("APP_CENTER_SOURCE_DIR")
	if source == "" {
		source = filepath.Join("..", "..", "..", "iwut-app-center-ddd")
	}
	source, e := filepath.Abs(source)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(source, "go.mod")); e != nil {
		t.Skip("actual App Center checkout unavailable; set APP_CENTER_SOURCE_DIR")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "app-center")
	buildArgs := []string{"build", "-o", binary}
	// A test-only overlay changes DNS transport, not App policy or repositories.
	// It is never written to the App checkout or compiled by production builds.
	for _, override := range overrides {
		if override["AUTH_E2E_DNS_ADDR"] != "" {
			fixture := filepath.Join(dir, "oauth_dns_fixture.go")
			code := []byte(`package main
import("context";"net";"os")
func init(){net.DefaultResolver=&net.Resolver{PreferGo:true,Dial:func(ctx context.Context,network,address string)(net.Conn,error){return (&net.Dialer{}).DialContext(ctx,network,os.Getenv("AUTH_E2E_DNS_ADDR"))}}}
`)
			if e := os.WriteFile(fixture, code, 0600); e != nil {
				t.Fatal(e)
			}
			overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(source, "cmd/app-center/oauth_dns_fixture.go"): fixture}})
			path := filepath.Join(dir, "overlay.json")
			if e := os.WriteFile(path, overlay, 0600); e != nil {
				t.Fatal(e)
			}
			buildArgs = append(buildArgs, "-overlay", path)
		}
	}
	buildArgs = append(buildArgs, "./cmd/app-center")
	build := exec.CommandContext(t.Context(), "go", buildArgs...)
	build.Dir = source
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build actual App Center: %v\n%s", e, output)
	}
	database := "auth_app_integration_" + uuid.NewString()
	client, e := mongo.NewClient(uri)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Database(database).Drop(context.Background()); client.Disconnect(context.Background()) })
	env := []string{}
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "APP_CENTER_") {
			env = append(env, v)
		}
	}
	httpAddr, grpcAddr := reserveAddress(t), reserveAddress(t)
	values := map[string]string{"APP_CENTER_MONGO_URI": uri, "APP_CENTER_MONGO_DATABASE": database, "APP_CENTER_HTTP_ADDR": httpAddr, "APP_CENTER_GRPC_ADDR": grpcAddr, "APP_CENTER_IDENTITY_ISSUER": "identity-test", "APP_CENTER_IDENTITY_PUBLIC_KEYS": "identity-k1=" + keyFile, "APP_CENTER_AUTH_SCOPE_CATALOG_GRPC_TARGET": authTarget, "APP_CENTER_SERVICE_IDENTITY_ID": "app-center", "APP_CENTER_SERVICE_IDENTITY_KID": "app-center-2026-01", "APP_CENTER_SERVICE_IDENTITY_PRIVATE_KEY_PEM_B64": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serviceKey)})), "APP_CENTER_INITIAL_APPLICATION_QUOTA": "1"}
	publicDER, e := x509.MarshalPKIXPublicKey(&serviceKey.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	callerRegistry, _ := json.Marshal(map[string]any{"iwut-auth-center": map[string]any{"status": "ACTIVE", "keys": map[string]any{"auth-service": map[string]string{"publicKeyPemB64": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))}}, "permissions": []string{"app.oauth.client.read", "app.oauth.client.verify", "app.oauth.runtime.resolve", "app.oauth.context.resolve", "app.oauth.redirects.read"}}})
	values["APP_CENTER_SERVICE_CALLERS_B64"] = base64.StdEncoding.EncodeToString(callerRegistry)
	for _, override := range overrides {
		for k, v := range override {
			values[k] = v
		}
	}
	grpcAddr = values["APP_CENTER_GRPC_ADDR"]
	httpAddr = values["APP_CENTER_HTTP_ADDR"]
	for k, v := range values {
		env = append(env, k+"="+v)
	}
	migration := exec.CommandContext(t.Context(), binary, "migrate")
	migration.Env = env
	if output, e := migration.CombinedOutput(); e != nil {
		t.Fatalf("App migrations: %v\n%s", e, output)
	}
	logFile, e := os.Create(filepath.Join(dir, "app.log"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	process := exec.CommandContext(t.Context(), binary, "serve")
	process.Env = env
	process.Stdout = logFile
	process.Stderr = logFile
	if e = process.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = process.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = process.Process.Kill()
			<-done
		}
		if t.Failed() {
			data, _ := os.ReadFile(logFile.Name())
			t.Logf("App Center output: %s", data)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	conn, e := grpc.DialContext(ctx, grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, "http://" + httpAddr, client.Database(database)
}

func developerActualAppFlow(t *testing.T, uri, keyFile, authTarget string, serviceKey *rsa.PrivateKey, authID string, issue func(string) string) {
	conn, _, db := startActualApp(t, uri, keyFile, authTarget, serviceKey)
	token := issue("iwut-app-center")
	call := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", token))
	application := apppb.NewApplicationClient(conn)
	created, e := application.CreateApplication(call, &apppb.CreateApplicationRequest{Name: "Developer_Onboarding"})
	if e != nil || created.GetAdminId() != authID {
		t.Fatal(created, e)
	}
	if _, e = application.CreateApplication(call, &apppb.CreateApplicationRequest{Name: "Quota_Still_Applies"}); status.Code(e) != codes.ResourceExhausted {
		t.Fatal("App quota bypassed", e)
	}
	versionID, _ := uuid.NewV7()
	reviewID, _ := uuid.NewV7()
	_, e = reviewpb.NewApplicationReviewClient(conn).DecideApplicationVersionReview(call, &reviewpb.DecideApplicationVersionReviewRequest{ApplicationId: created.Id, VersionId: versionID.String(), ReviewId: reviewID.String()})
	if status.Code(e) != codes.PermissionDenied {
		t.Fatal("developer gained reviewer access", e)
	}
	var stored bson.M
	if e = db.Collection("applications").FindOne(t.Context(), bson.M{"id": created.Id}).Decode(&stored); e != nil || stored["adminId"] != authID {
		t.Fatal(stored, e)
	}
	t.Log("Actual App Center production verifier accepted newly issued Auth JWS; real application creation persisted, quota and reviewer gate held")
}
