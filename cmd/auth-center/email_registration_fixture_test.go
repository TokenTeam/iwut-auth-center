package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	emailpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/testutil/smtpcapture"
)

var registrationSMTP sync.Map

// This fixture always runs the production TLS SMTP sender and generated email
// client. It cannot create a USER by inserting fixture state or calling retired RPCs.
func enableEmailRegistrationFixture(t *testing.T, env map[string]string, captures ...*smtpcapture.Server) *smtpcapture.Server {
	t.Helper()
	var capture *smtpcapture.Server
	if len(captures) > 0 {
		capture = captures[0]
	} else {
		capture = smtpcapture.New(t, "implicit_tls")
		ca := filepath.Join(t.TempDir(), "registration-smtp-ca.pem")
		if err := os.WriteFile(ca, capture.CAPEM, 0600); err != nil {
			t.Fatal(err)
		}
		env["AUTH_SMTP_ADDR"] = capture.Address
		env["AUTH_SMTP_FROM"] = "auth@example.test"
		env["AUTH_SMTP_TLS_MODE"] = "implicit_tls"
		env["AUTH_SMTP_CA_FILE"] = ca
	}
	env["AUTH_EMAIL_BINDING_ENABLED"] = "true"
	env["AUTH_PASSWORD_ENABLED"] = "true"
	env["AUTH_PASSWORD_OPERATION_HMAC_KEY"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
	contentDigest := sha256.Sum256([]byte("blocked-test-password"))
	content := []byte(hex.EncodeToString(contentDigest[:]) + "\n")
	path := filepath.Join(t.TempDir(), "test-password-blocklist.txt")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	sha := sha256.Sum256(content)
	env["AUTH_PASSWORD_BLOCKLIST_FILE"] = path
	env["AUTH_PASSWORD_BLOCKLIST_VERSION"] = "fixture-v1"
	env["AUTH_PASSWORD_BLOCKLIST_SOURCE"] = "controlled-test-fixture-not-production"
	env["AUTH_PASSWORD_BLOCKLIST_SHA256"] = hex.EncodeToString(sha[:])
	env["AUTH_PASSWORD_READINESS_CONFIRMED"] = "true"

	if env["AUTH_EMAIL_BINDING_HMAC_KEY"] == "" {
		env["AUTH_EMAIL_BINDING_HMAC_KEY"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	}
	// Some governance fixtures enroll many users from one loopback source.
	env["AUTH_EMAIL_SOURCE_HOURLY"] = "1000"
	rememberRegistrationSMTP(t, env[config.GRPCAddrEnv], capture)
	return capture
}
func rememberRegistrationSMTP(t *testing.T, address string, capture *smtpcapture.Server) {
	t.Helper()
	registrationSMTP.Store(address, capture)
	t.Cleanup(func() { registrationSMTP.Delete(address) })
}
func addVerifiedEmail(t *testing.T, conn *grpc.ClientConn, token, address string) *emailpb.OwnEmails {
	t.Helper()
	value, ok := registrationSMTP.Load(conn.Target())
	if !ok {
		t.Fatal("missing controlled registration SMTP")
	}
	capture := value.(*smtpcapture.Server)
	client := emailpb.NewEmailAccountServiceClient(conn)
	ctx := sessionCallContext(t.Context(), token)
	own, err := client.GetOwnEmails(ctx, &emailpb.GetOwnEmailsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	started, err := client.BeginAddOwnEmail(ctx, &emailpb.BeginAddOwnEmailRequest{RequestId: uuid.NewString(), Email: address, ExpectedDirectoryRevision: own.DirectoryRevision})
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(capture.Next(t).Body)
	if len(match) != 2 {
		t.Fatal("missing ADD code")
	}
	added, err := client.CompleteAddOwnEmail(ctx, &emailpb.CompleteAddOwnEmailRequest{OperationId: started.OperationId, Code: match[1]})
	if err != nil {
		t.Fatal(err)
	}
	return added.Emails
}
func addAndSwitchLoginEmail(t *testing.T, conn *grpc.ClientConn, token, address string) {
	t.Helper()
	emails := addVerifiedEmail(t, conn, token, address)
	target := ""
	for _, b := range emails.Emails {
		if b.Email == address {
			target = b.BindingId
		}
	}
	client := emailpb.NewEmailAccountServiceClient(conn)
	if _, err := client.SwitchOwnLoginEmail(sessionCallContext(t.Context(), token), &emailpb.SwitchOwnLoginEmailRequest{RequestId: uuid.NewString(), TargetBindingId: target, CurrentPassword: "a long fixture password 123", ExpectedDirectoryRevision: emails.DirectoryRevision, ExpectedLoginRoleRevision: emails.LoginRoleRevision}); err != nil {
		t.Fatal(err)
	}
}

func registerUser(t *testing.T, conn *grpc.ClientConn, key *ecdsa.PrivateKey, _ []byte) (*authpb.UserRegistrationResult, *emailpb.CompleteEmailRegistrationRequest) {
	t.Helper()
	value, ok := registrationSMTP.Load(conn.Target())
	if !ok {
		t.Fatal("email registration fixture must enable controlled TLS SMTP before Wire construction")
	}
	capture := value.(*smtpcapture.Server)
	client := emailpb.NewEmailAccountServiceClient(conn)
	public := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	email := uuid.NewString() + "@example.test"
	started, err := client.BeginEmailRegistration(t.Context(), &emailpb.BeginEmailRegistrationRequest{RequestId: uuid.NewString(), Email: email, CredentialProposal: &authpb.CredentialRegistrationProposal{ProtocolVersion: "iwut-device-v1", PublicKey: public}})
	if err != nil {
		t.Fatal(err)
	}
	if started.ProtocolVersion != "iwut-email-registration-v3" {
		t.Fatal("unexpected registration version")
	}
	expires := make([]byte, 8)
	binary.BigEndian.PutUint64(expires, uint64(started.ExpiresAtUnixMs))
	expected := deviceprotocol.Frame([]byte("iwut-email-registration-proof-v3"), []byte("iwut-email-registration-v3"), []byte("REGISTER_WITH_PASSWORD_EMAIL"), []byte("iwut-auth-center:test"), []byte("iwut-client"), []byte(started.OperationId), started.Challenge, expires, public, []byte(email))
	if !bytes.Equal(expected, started.SigningPayload) || !time.Now().Before(time.UnixMilli(started.ExpiresAtUnixMs)) {
		t.Fatal("unexpected registration context")
	}
	message := capture.Next(t)
	match := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(message.Body)
	if len(match) != 2 {
		t.Fatal("registration SMTP code missing")
	}
	proof := &emailpb.CompleteEmailRegistrationRequest{OperationId: started.OperationId, Code: match[1], Password: "a long fixture password 123", Proof: &authpb.CredentialProof{Signature: signDevice(t, key, expected)}}
	activated, err := client.CompleteEmailRegistration(t.Context(), proof)
	if err != nil {
		t.Fatal(err)
	}
	if activated.RegistrationResult == nil {
		t.Fatal("email registration did not atomically activate binding")
	}
	return activated.RegistrationResult, proof
}
