package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/password_login"
	pwdpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/password_management"
	emailpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestE2E_PasswordLogin_ProductionWireAndReset(t *testing.T) {
	f := newPasswordWireFixture(t, map[string]string{"AUTH_PASSWORD_LOGIN_ENABLED": "true"})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registered, _ := registerUser(t, f.conn, key, nil)
	emails, err := emailpb.NewEmailAccountServiceClient(f.conn).GetOwnEmails(sessionCallContext(t.Context(), registered.Session.SessionToken), &emailpb.GetOwnEmailsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	address := emails.Emails[0].Email
	login := pb.NewPasswordLoginServiceClient(f.conn)
	httpCall := func(path, body string, want int) []byte {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, "http://"+f.env[config.HTTPAddrEnv]+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal(path, resp.StatusCode, string(data), resp.Header)
		}
		return data
	}
	for _, body := range []string{`{"requestId":null}`, `{"operationId":"id","password":"secret","proof":null}`, `{"operationId":"id","password":"secret","proof":{"signature":"AA==","signature":"AA=="}}`} {
		if data := httpCall("/v1/password-logins:complete", body, 400); strings.Contains(string(data), "secret") {
			t.Fatal("password echoed")
		}
	}
	httpCall("/v1/password-logins", strings.Repeat(" ", 16385)+"{}", 413)
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proposal := &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: elliptic.Marshal(elliptic.P256(), newKey.X, newKey.Y)}
	begin := &pb.BeginPasswordLoginRequest{RequestId: uuid.NewString(), LoginEmail: address, CredentialProposal: proposal}
	body, _ := protojson.Marshal(begin)
	var challenge pb.PasswordLoginStarted
	if err = protojson.Unmarshal(httpCall("/v1/password-logins", string(body), 200), &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.ProtocolVersion != "iwut-password-login-v1" || len(challenge.Challenge) != 32 || strings.Contains(string(challenge.SigningPayload), registered.AuthId) {
		t.Fatal("invalid or revealing challenge")
	}
	if _, err = login.BeginPasswordLogin(metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-session", "")), begin); status.Code(err) != codes.InvalidArgument {
		t.Fatal("present empty carrier accepted", err)
	}
	complete := &pb.CompletePasswordLoginRequest{OperationId: challenge.OperationId, Password: "a long fixture password 123", Proof: &authpb.CredentialProof{Signature: signDevice(t, newKey, challenge.SigningPayload)}}
	result, err := login.CompletePasswordLogin(t.Context(), complete)
	if err != nil || result.AuthId != registered.AuthId || result.Session == nil || result.Session.SessionToken == "" {
		t.Fatal(result, err)
	}
	if _, err = login.CompletePasswordLogin(t.Context(), complete); status.Code(err) != codes.AlreadyExists {
		t.Fatal("token disclosed twice", err)
	}
	// Actual current Session consumption uses PASSWORD_AND_DEVICE, not an enum-only test.
	if _, err = emailpb.NewEmailAccountServiceClient(f.conn).GetOwnEmails(sessionCallContext(t.Context(), result.Session.SessionToken), &emailpb.GetOwnEmailsRequest{}); err != nil {
		t.Fatal(err)
	}
	// Reset has no login side effect. All old keys stay retired, but the same
	// account can explicitly log in using its new password and a fresh key.
	if _, err = f.db.Collection(ma.EmailQuotaCollection).DeleteMany(t.Context(), bson.M{}); err != nil {
		t.Fatal(err)
	}
	passwords := pwdpb.NewPasswordManagementServiceClient(f.conn)
	reset, err := passwords.BeginPasswordReset(t.Context(), &pwdpb.BeginPasswordResetRequest{RequestId: uuid.NewString(), LoginEmail: address})
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(f.capture.Next(t).Body)
	if len(match) != 2 {
		t.Fatal("missing reset code")
	}
	if _, err = passwords.CompletePasswordReset(t.Context(), &pwdpb.CompletePasswordResetRequest{OperationId: reset.OperationId, Code: match[1], NewPassword: "a fresh reset password 789"}); err != nil {
		t.Fatal(err)
	}
	f.capture.Next(t)
	if _, err = emailpb.NewEmailAccountServiceClient(f.conn).GetOwnEmails(sessionCallContext(t.Context(), result.Session.SessionToken), &emailpb.GetOwnEmailsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("reset retained Session", err)
	}
	retired, err := login.BeginPasswordLogin(t.Context(), &pb.BeginPasswordLoginRequest{RequestId: uuid.NewString(), LoginEmail: address, CredentialProposal: proposal})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = login.CompletePasswordLogin(t.Context(), &pb.CompletePasswordLoginRequest{OperationId: retired.OperationId, Password: "a fresh reset password 789", Proof: &authpb.CredentialProof{Signature: signDevice(t, newKey, retired.SigningPayload)}}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("retired key revived", err)
	}
	fresh, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	freshBegin, err := login.BeginPasswordLogin(t.Context(), &pb.BeginPasswordLoginRequest{RequestId: uuid.NewString(), LoginEmail: address, CredentialProposal: &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: elliptic.Marshal(elliptic.P256(), fresh.X, fresh.Y)}})
	if err != nil {
		t.Fatal(err)
	}
	finalBody, _ := protojson.Marshal(&pb.CompletePasswordLoginRequest{OperationId: freshBegin.OperationId, Password: "a fresh reset password 789", Proof: &authpb.CredentialProof{Signature: signDevice(t, fresh, freshBegin.SigningPayload)}})
	var final pb.PasswordLoginResult
	if err = protojson.Unmarshal(httpCall("/v1/password-logins:complete", string(finalBody), 200), &final); err != nil || final.AuthId != registered.AuthId || final.CredentialId == result.CredentialId {
		t.Fatal(&final, err)
	}
	if _, err = emailpb.NewEmailAccountServiceClient(f.conn).GetOwnEmails(sessionCallContext(t.Context(), final.Session.SessionToken), &emailpb.GetOwnEmailsRequest{}); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.db.Collection(ma.PasswordAuditCollection).CountDocuments(t.Context(), bson.M{"action": "PASSWORD_LOGIN"}); n != 2 {
		t.Fatal("login audit count", n)
	}
	if n, _ := f.db.Collection(ma.PasswordNotificationCollection).CountDocuments(t.Context(), bson.M{}); n != 1 {
		t.Fatal("password login emitted mail event", n)
	}
}
func TestE2E_PasswordLogin_DefaultOff(t *testing.T) {
	f := newPasswordWireFixture(t, nil)
	if _, err := pb.NewPasswordLoginServiceClient(f.conn).BeginPasswordLogin(t.Context(), &pb.BeginPasswordLoginRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+f.env[config.HTTPAddrEnv]+"/v1/password-logins", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
}
