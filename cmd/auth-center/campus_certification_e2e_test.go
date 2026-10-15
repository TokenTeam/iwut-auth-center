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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	campuspb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/campus_certification"
	emailpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	mongoadapter "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/testutil/smtpcapture"
)

// This suite uses production Wire/listeners, real TLS SMTP and real Mongo;
// no client-supplied school identity or direct database certification grant.
func TestE2E_CampusCertification_ProductionWireAndRegistration(t *testing.T) {
	uri := os.Getenv(mongoIntegrationURIEnv)
	if uri == "" {
		t.Skip("run make test-mongo")
	}
	capture := smtpcapture.New(t, "implicit_tls")
	_, callers := testServiceCallerRegistry(t)
	identityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile, catalogFile, caFile := filepath.Join(dir, "identity.pem"), filepath.Join(dir, "profile.json"), filepath.Join(dir, "smtp-ca.pem")
	for path, data := range map[string][]byte{keyFile: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), catalogFile: []byte(`{"definitions":[]}`), caFile: capture.CAPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	keys, _ := json.Marshal(map[string]string{"test": keyFile})
	dbName := "uc031_wire_" + uuid.NewString()
	env := map[string]string{
		config.UserEndpointsEnabledEnv: "true", config.MongoURIEnv: uri, config.MongoDatabaseEnv: dbName,
		config.ServiceCallersEnv: callers, config.HTTPAddrEnv: reserveAddress(t), config.GRPCAddrEnv: reserveAddress(t),
		"AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h",
		"AUTH_PROFILE_CATALOG_FILE": catalogFile, "AUTH_USER_IDENTITY_ISSUER": "test", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keys),
		"AUTH_EMAIL_BINDING_ENABLED": "true", "AUTH_EMAIL_BINDING_HMAC_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
		"AUTH_CAMPUS_CERTIFICATION_ENABLED": "true", "AUTH_CAMPUS_CERTIFICATION_CODE_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)),
		"AUTH_SMTP_ADDR": capture.Address, "AUTH_SMTP_FROM": "auth@example.test", "AUTH_SMTP_TLS_MODE": "implicit_tls", "AUTH_SMTP_CA_FILE": caFile,
		// Retired variables, even malformed leftovers, are not startup gates.
		"AUTH_ASSOC_KEY_VERSION": "retired", "AUTH_ASSOC_ENCRYPT_KEY": "not-a-key", "AUTH_ASSOC_PREVIOUS_LOOKUP_KEY": "bad",
	}
	enableEmailRegistrationFixture(t, env, capture)
	load := func() config.Config {
		cfg, e := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
		if e != nil {
			t.Fatal(e)
		}
		return cfg
	}
	databaseClient, err := mongoadapter.NewClient(uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = databaseClient.Database(dbName).Drop(context.Background())
		_ = databaseClient.Disconnect(context.Background())
	})
	app, cleanup, err := wireApp(load())
	if err != nil {
		t.Fatal(err)
	}
	conn, stop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	emailClient := emailpb.NewEmailAccountServiceClient(conn)
	campusClient := campuspb.NewCampusCertificationServiceClient(conn)
	codePattern := regexp.MustCompile(`Verification code: ([0-9]{8})`)
	nextCode := func() string {
		m := capture.Next(t)
		matched := codePattern.FindStringSubmatch(m.Body)
		if len(matched) != 2 {
			t.Fatalf("missing verification code: %s", m.Body)
		}
		return matched[1]
	}
	register := func(email string) *authpb.UserRegistrationResult {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		started, e := emailClient.BeginEmailRegistration(t.Context(), &emailpb.BeginEmailRegistrationRequest{RequestId: uuid.NewString(), Email: email, CredentialProposal: &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: elliptic.Marshal(elliptic.P256(), key.X, key.Y)}})
		if e != nil {
			t.Fatal(e)
		}
		if started.GetProtocolVersion() != "iwut-email-registration-v3" {
			t.Fatal("not v3 signup")
		}
		result, e := emailClient.CompleteEmailRegistration(t.Context(), &emailpb.CompleteEmailRegistrationRequest{OperationId: started.OperationId, Code: nextCode(), Password: "a long fixture password 123", Proof: &authpb.CredentialProof{Signature: signDevice(t, key, started.SigningPayload)}})
		if e != nil {
			t.Fatal(e)
		}
		return result.RegistrationResult
	}
	ordinary := register("ordinary@example.test")
	ctx := sessionCallContext(t.Context(), ordinary.Session.SessionToken)
	if _, e := campusClient.GetOwnCampusCertification(t.Context(), &campuspb.GetOwnCampusCertificationRequest{}); status.Code(e) != codes.Unauthenticated {
		t.Fatalf("anonymous campus query: %v", e)
	}
	for _, values := range [][]string{{""}, {"bad"}, {ordinary.Session.SessionToken, ordinary.Session.SessionToken}} {
		bad := metadata.NewOutgoingContext(t.Context(), metadata.MD{"x-iwut-session": values})
		if _, e := campusClient.GetOwnCampusCertification(bad, &campuspb.GetOwnCampusCertificationRequest{}); status.Code(e) != codes.Unauthenticated {
			t.Fatalf("carrier accepted: %v", e)
		}
	}
	blank, e := campusClient.GetOwnCampusCertification(ctx, &campuspb.GetOwnCampusCertificationRequest{})
	if e != nil || blank.Certified || blank.CertifiedAtUnixMs != nil || blank.Institution != "WHUT" {
		t.Fatalf("ordinary mailbox certified: %v %v", blank, e)
	}
	for _, address := range []string{"student@other.whut.edu.cn", "student@whut.edu.cn.evil.test", "student@example.test"} {
		if _, e := campusClient.BeginOwnCampusCertification(ctx, &campuspb.BeginOwnCampusCertificationRequest{RequestId: uuid.NewString(), Email: address}); status.Code(e) != codes.InvalidArgument {
			t.Fatalf("accepted %s: %v", address, e)
		}
	}
	request := &campuspb.BeginOwnCampusCertificationRequest{RequestId: uuid.NewString(), Email: " Student@WHUT.EDU.CN "}
	started, e := campusClient.BeginOwnCampusCertification(ctx, request)
	if e != nil {
		t.Fatal(e)
	}
	if started.TargetEmail != "student@whut.edu.cn" {
		t.Fatal("campus address not normalized")
	}
	code := nextCode()
	if again, e := campusClient.BeginOwnCampusCertification(ctx, request); e != nil || again.OperationId != started.OperationId {
		t.Fatalf("Begin replay: %v", e)
	}
	// Duplicate wire fields are rejected before protobuf can discard the first.
	duplicate := &campuspb.BeginOwnCampusCertificationRequest{RequestId: uuid.NewString(), Email: "different@whut.edu.cn"}
	duplicate.ProtoReflect().SetUnknown(protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), uuid.NewString()))
	if _, e := campusClient.BeginOwnCampusCertification(ctx, duplicate); status.Code(e) != codes.InvalidArgument {
		t.Fatalf("duplicate wire accepted: %v", e)
	}
	other := register("other@example.test")
	if _, e := campusClient.CompleteOwnCampusCertification(sessionCallContext(t.Context(), other.Session.SessionToken), &campuspb.CompleteOwnCampusCertificationRequest{OperationId: started.OperationId, Code: code}); status.Code(e) != codes.InvalidArgument {
		t.Fatalf("cross-account completion: %v", e)
	}
	base := "http://" + env[config.HTTPAddrEnv]
	completionURL := base + "/v1/users/me/campus-certification/verifications/" + started.OperationId + "/completion"
	doHTTP := func(method, url, body, token string) (int, []byte) {
		req, e := http.NewRequest(method, url, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("x-iwut-session", token)
		}
		response, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		data, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("campus response cacheable")
		}
		return response.StatusCode, data
	}
	for _, body := range []string{`{"code":"` + code + `","code":"` + code + `"}`, `{"code":"` + code + `","unknown":"secret"}`} {
		if status, _ := doHTTP("POST", completionURL, body, ordinary.Session.SessionToken); status != 400 {
			t.Fatalf("invalid JSON accepted: %d", status)
		}
	}
	if status, _ := doHTTP("POST", completionURL+"?code="+code, `{}`, ordinary.Session.SessionToken); status != 400 {
		t.Fatalf("query accepted: %d", status)
	}
	statusCode, body := doHTTP("POST", completionURL, `{"operationId":"body-does-not-authorize","code":"`+code+`"}`, ordinary.Session.SessionToken)
	if statusCode != 200 {
		t.Fatalf("HTTP completion: %d %s", statusCode, body)
	}
	var certified campuspb.OwnCampusCertification
	if e := protojson.Unmarshal(body, &certified); e != nil || !certified.Certified || certified.CertifiedAtUnixMs == nil {
		t.Fatalf("bad fact: %s %v", body, e)
	}
	if again, e := campusClient.CompleteOwnCampusCertification(ctx, &campuspb.CompleteOwnCampusCertificationRequest{OperationId: started.OperationId, Code: code}); e != nil || again.GetCertifiedAtUnixMs() != certified.GetCertifiedAtUnixMs() {
		t.Fatalf("completion replay changes fact: %v %v", again, e)
	}
	active, e := emailClient.GetOwnEmails(ctx, &emailpb.GetOwnEmailsRequest{})
	if e != nil || len(active.Emails) != 2 || active.LoginRoleRevision != 1 {
		t.Fatal("campus ADD modified role", active, e)
	}
	var campusID string
	for _, b := range active.Emails {
		if b.Email == "ordinary@example.test" && !b.IsLogin {
			t.Fatal("primary role changed")
		}
		if b.IsWhut {
			campusID = b.BindingId
		}
	}
	db := databaseClient.Database(dbName)
	if n, e := db.Collection(mongoadapter.CampusCertificationCollection).CountDocuments(t.Context(), bson.M{}); e != nil || n != 0 {
		t.Fatal("legacy permanent fact written", n, e)
	}
	removed, e := emailClient.RemoveOwnEmail(ctx, &emailpb.RemoveOwnEmailRequest{RequestId: uuid.NewString(), BindingId: campusID, ExpectedDirectoryRevision: active.DirectoryRevision})
	if e != nil || removed.Emails.LoginRoleRevision != 1 {
		t.Fatal("campus remove", removed, e)
	}
	// An old permanent fact cannot resurrect membership after its last basis is removed.
	if _, e = db.Collection(mongoadapter.CampusCertificationCollection).InsertOne(t.Context(), bson.M{"authId": ordinary.AuthId, "institution": "WHUT", "certifiedAt": time.Now().UTC().Truncate(time.Millisecond)}); e != nil {
		t.Fatal(e)
	}
	absent, e := campusClient.GetOwnCampusCertification(ctx, &campuspb.GetOwnCampusCertificationRequest{})
	if e != nil || absent.Certified {
		t.Fatal("old fact restored certification", absent, e)
	}

	for _, collection := range []string{mongoadapter.AssociationCollection, mongoadapter.AssociationMemberCollection} {
		if n, e := db.Collection(collection).CountDocuments(t.Context(), bson.M{}); e != nil || n != 0 {
			t.Fatalf("registration still writes %s: %d %v", collection, n, e)
		}
	}
	stop()
	stop = nil
	env["AUTH_CAMPUS_CERTIFICATION_ENABLED"] = "false"
	env[config.HTTPAddrEnv], env[config.GRPCAddrEnv] = reserveAddress(t), reserveAddress(t)
	app, cleanup, e = wireApp(load())
	if e != nil {
		t.Fatal(e)
	}
	conn, stop = startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	emailClient = emailpb.NewEmailAccountServiceClient(conn)
	campusClient = campuspb.NewCampusCertificationServiceClient(conn)
	if _, e := campusClient.GetOwnCampusCertification(ctx, &campuspb.GetOwnCampusCertificationRequest{}); status.Code(e) != codes.Unimplemented {
		t.Fatalf("disabled RPC: %v", e)
	}
	base = "http://" + env[config.HTTPAddrEnv]
	if status, _ := doHTTP("GET", base+"/v1/users/me/campus-certification", "", ordinary.Session.SessionToken); status != 404 {
		t.Fatalf("disabled HTTP: %d", status)
	}
	automatic := register("automatic@whut.edu.cn")
	if fact, e := mongoadapter.ReadCurrentCampusBasisTx(t.Context(), db, automatic.AuthId); e != nil || !fact.Valid() {
		t.Fatal("disabled alias suppressed current registration basis", fact, e)
	}
}
