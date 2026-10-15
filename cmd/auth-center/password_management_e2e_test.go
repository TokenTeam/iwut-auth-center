package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	loginpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_login"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/password_management"
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
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestE2E_PasswordManagement_ProductionWire(t *testing.T) {
	f := newPasswordWireFixture(t, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registered, _ := registerUser(t, f.conn, key, nil)
	ctx := sessionCallContext(t.Context(), registered.Session.SessionToken)
	service := pb.NewPasswordManagementServiceClient(f.conn)
	emails, err := emailpb.NewEmailAccountServiceClient(f.conn).GetOwnEmails(ctx, &emailpb.GetOwnEmailsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	address := emails.Emails[0].Email
	httpCall := func(path, body, token string, want int) []byte {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, "http://"+f.env[config.HTTPAddrEnv]+path, strings.NewReader(body))
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
		if resp.StatusCode != want || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal(path, resp.StatusCode, string(data), resp.Header)
		}
		return data
	}
	for _, body := range []string{`{"requestId":null,"currentPassword":"secret","newPassword":"secret"}`, `{"requestId":"id","current_password":"secret","newPassword":"secret"}`, `{"requestId":"id","requestId":"other","currentPassword":"secret","newPassword":"secret"}`} {
		response := httpCall("/v1/users/me/password:change", body, registered.Session.SessionToken, 400)
		if strings.Contains(string(response), "secret") {
			t.Fatal("secret echoed")
		}
	}
	httpCall("/v1/users/me/password:change", strings.Repeat(" ", 16385)+"{}", registered.Session.SessionToken, 413)
	request := uuid.NewString()
	body := `{"requestId":"` + request + `","currentPassword":"a long fixture password 123","newPassword":"a long changed password 456"}`
	var changed pb.PasswordChanged
	if err = protojson.Unmarshal(httpCall("/v1/users/me/password:change", body, registered.Session.SessionToken, 200), &changed); err != nil {
		t.Fatal(err)
	}
	if changed.Session == nil || changed.Session.SessionToken == registered.Session.SessionToken {
		t.Fatal("missing new Session")
	}
	notification := f.capture.Next(t)
	if !strings.Contains(notification.Body, "iWUT password security notification") || strings.Contains(notification.Body, "password 456") {
		t.Fatal("unsafe notification")
	}
	if _, err = service.GetOwnPasswordChange(ctx, &pb.GetOwnPasswordChangeRequest{RequestId: request}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("old Session accepted", err)
	}
	newCtx := sessionCallContext(t.Context(), changed.Session.SessionToken)
	result, err := service.GetOwnPasswordChange(newCtx, &pb.GetOwnPasswordChangeRequest{RequestId: request})
	if err != nil || result.Status != pb.PasswordChangeStatus_COMPLETED || result.GetOperationId() != changed.OperationId {
		t.Fatal(result, err)
	}
	if _, err = service.BeginPasswordReset(newCtx, &pb.BeginPasswordResetRequest{RequestId: uuid.NewString(), LoginEmail: address}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("Session reset carrier accepted", err)
	}
	// The shared send cooldown is not bypassed by changing from registration to reset.
	if _, err = service.BeginPasswordReset(t.Context(), &pb.BeginPasswordResetRequest{RequestId: uuid.NewString(), LoginEmail: address}); status.Code(err) != codes.ResourceExhausted {
		t.Fatal("shared cooldown bypassed", err)
	}
	// Isolated send-budget reset avoids a real minute sleep in this fixture.
	if _, err = f.db.Collection(ma.EmailQuotaCollection).DeleteMany(t.Context(), bson.M{}); err != nil {
		t.Fatal(err)
	}
	started, err := service.BeginPasswordReset(t.Context(), &pb.BeginPasswordResetRequest{RequestId: uuid.NewString(), LoginEmail: address})
	if err != nil {
		t.Fatal(err)
	}
	mail := f.capture.Next(t)
	match := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(mail.Body)
	if len(match) != 2 {
		t.Fatal("missing reset code")
	}
	resetBody := `{"operationId":"` + started.OperationId + `","code":"` + match[1] + `","newPassword":"another secure reset password 789"}`
	httpCall("/v1/password-resets:complete", resetBody, "", 200)
	if _, err = service.CompletePasswordReset(t.Context(), &pb.CompletePasswordResetRequest{OperationId: started.OperationId, Code: match[1], NewPassword: "another secure reset password 789"}); err != nil {
		t.Fatal("completed retry failed", err)
	}
	if _, err = service.GetOwnPasswordChange(newCtx, &pb.GetOwnPasswordChangeRequest{RequestId: request}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("reset retained Session", err)
	}
	f.capture.Next(t) // The reliable worker delivers the separate reset notification.
	if _, err = f.db.Collection(ma.EmailQuotaCollection).DeleteMany(t.Context(), bson.M{}); err != nil {
		t.Fatal(err)
	}
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	login := loginpb.NewEmailLoginServiceClient(f.conn)
	challenge, err := login.BeginEmailLogin(t.Context(), &loginpb.BeginEmailLoginRequest{RequestId: uuid.NewString(), Email: address, CredentialProposal: &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: elliptic.Marshal(elliptic.P256(), newKey.X, newKey.Y)}})
	if err != nil {
		t.Fatal(err)
	}
	match = regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(f.capture.Next(t).Body)
	if len(match) != 2 {
		t.Fatal("missing recovery code")
	}
	recovered, err := login.CompleteEmailLogin(t.Context(), &loginpb.CompleteEmailLoginRequest{OperationId: challenge.OperationId, Code: match[1], Proof: &authpb.CredentialProof{Signature: signDevice(t, newKey, challenge.SigningPayload)}})
	if err != nil || recovered.AuthId != registered.AuthId || recovered.CredentialId == registered.CredentialId {
		t.Fatal(recovered, err)
	}
	// A committed but unacknowledged notification survives closing the public
	// gate; replaying delivery never repeats its password mutation.
	f.stop()
	_, err = f.db.Collection(ma.PasswordNotificationCollection).UpdateOne(t.Context(), bson.M{"eventId": started.OperationId}, bson.M{"$set": bson.M{"state": "PENDING", "attempts": int64(0), "nextAttemptAt": time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	f.env["AUTH_PASSWORD_MANAGEMENT_ENABLED"] = "false"
	c, err := config.Load(func(k string) (string, bool) { v, ok := f.env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	app, cleanup, err := wireApp(c)
	if err != nil {
		t.Fatal(err)
	}
	_, stop := startUserApp(t, app, cleanup, f.env[config.GRPCAddrEnv])
	defer stop()
	httpCall("/v1/password-resets", "{}", "", 404)
	if !strings.Contains(f.capture.Next(t).Body, "iWUT password security notification") {
		t.Fatal("disabled route stopped committed notification")
	}
}
func TestE2E_PasswordManagement_DefaultOff(t *testing.T) {
	f := newPasswordWireFixture(t, map[string]string{"AUTH_PASSWORD_MANAGEMENT_ENABLED": "false"})
	if _, err := pb.NewPasswordManagementServiceClient(f.conn).BeginPasswordReset(t.Context(), &pb.BeginPasswordResetRequest{RequestId: uuid.NewString(), LoginEmail: "unknown@example.test"}); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+f.env[config.HTTPAddrEnv]+"/v1/password-resets", strings.NewReader(`{}`))
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
