package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	authv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	profilev1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	emailpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	authdomain "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/testutil/smtpcapture"
	"regexp"
)

// Called inside the real Mongo + production Wire lifecycle after cold migration.
// The same running process is exercised by both generated gRPC and HTTP clients.
func runHTTPUserFlow(t *testing.T, base string, identityKey *rsa.PrivateKey, capture *smtpcapture.Server) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	send := func(method, path, body string, headers http.Header, want int, response proto.Message) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header = headers.Clone()
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s: status %d want %d: %s", method, path, res.StatusCode, want, data)
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("missing no-store on %s", path)
		}
		if response != nil {
			if err := protojson.Unmarshal(data, response); err != nil {
				t.Fatal(err)
			}
		}
		return data
	}
	encode := func(value proto.Message) string {
		t.Helper()
		b, err := protojson.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proposal := &emailpb.BeginEmailRegistrationRequest{RequestId: uuid.NewString(), Email: uuid.NewString() + "@example.test", CredentialProposal: &authv1.CredentialRegistrationProposal{ProtocolVersion: authdomain.ProtocolVersion, PublicKey: elliptic.Marshal(elliptic.P256(), key.X, key.Y)}}
	var challenge emailpb.EmailRegistrationStarted
	send("POST", "/v1/registrations", `{}`, nil, 404, nil)
	send("POST", "/v3/email-registrations", encode(proposal), nil, 200, &challenge)
	match := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(capture.Next(t).Body)
	if len(match) != 2 {
		t.Fatal("HTTP registration missing SMTP code")
	}
	completion := encode(&emailpb.CompleteEmailRegistrationRequest{OperationId: challenge.OperationId, Code: match[1], Password: "a long fixture password 123", Proof: &authv1.CredentialProof{Signature: signDevice(t, key, challenge.GetSigningPayload())}})
	var activated emailpb.EmailRegistrationCompleted
	send("POST", "/v3/email-registrations:complete", completion, nil, 200, &activated)
	registered := activated.GetRegistrationResult()
	if registered.AuthId == "" || registered.Session.GetSessionToken() == "" {
		t.Fatal("HTTP registration returned no account/session")
	}
	send("POST", "/v3/email-registrations:complete", completion, nil, 409, nil)
	md, _ := metadata.FromOutgoingContext(userCallContext(t, identityKey, registered.AuthId))
	identity := http.Header{"X-Iwut-Identity": md.Get("x-iwut-identity")}
	session := http.Header{"X-Iwut-Session": {registered.Session.SessionToken}}
	send("GET", "/v1/users/me/profile", "", nil, 401, nil)
	send("GET", "/v1/users/me/profile", "", session, 401, nil)
	send("GET", "/v1/users/me/profile", "", http.Header{"X-Iwut-Identity": {identity.Get("X-Iwut-Identity"), identity.Get("X-Iwut-Identity")}}, 401, nil)
	var schema profilev1.ProfileEditingSchema
	send("GET", "/v1/user-profile-schema", "", identity, 200, &schema)
	if len(schema.Definitions) != 1 {
		t.Fatal("HTTP schema missing")
	}
	edit := `{"expectedRevision":"1","set":[{"key":"test.nickname","value":{"stringValue":"HTTP Alice"}}]}`
	var edited profilev1.EditOwnProfileResponse
	send("PATCH", "/v1/users/me/profile", edit, identity, 200, &edited)
	if !edited.Changed || edited.GetProfile().GetRevision() != 2 {
		t.Fatal("HTTP edit failed")
	}
	var profile profilev1.OwnUserProfileSnapshot
	send("GET", "/v1/users/me/profile", "", identity, 200, &profile)
	if profile.Revision != 2 || profile.Entries[0].Value.GetStringValue() != "HTTP Alice" {
		t.Fatal("HTTP profile mismatch")
	}
	send("PATCH", "/v1/users/me/profile", edit, identity, 409, nil)
	for _, bad := range []string{
		`{"expectedRevision":"2","set":null,"remove":["test.nickname"]}`,
		`{"expectedRevision":"2","remove":null,"set":[{"key":"test.nickname","value":{"stringValue":"x"}}]}`,
		`{"expectedRevision":"2","set":[{"key":"test.nickname","value":{"booleanValue":null,"stringValue":"x"}}]}`,
		`{"expectedRevision":"2","set":[{"key":"test.nickname","value":{"stringValue":"x","booleanValue":false}}]}`,
		`{"expectedRevision":"2","expected_revision":"2"}`,
		`{"expectedRevision":"2","unexpected":"secret-value"}`,
		`{"expectedRevision":"2","set":[{"key":"test.nickname","value":null}]}`,
	} {
		data := send("PATCH", "/v1/users/me/profile", bad, identity, 400, nil)
		if bytes.Contains(data, []byte("secret-value")) {
			t.Fatal("decoder leaked input")
		}
	}
	send("PATCH", "/v1/users/me/profile", strings.Repeat(" ", 128*1024+1), identity, 413, nil)
	send("POST", "/v1/device-logins", strings.Repeat(" ", 16*1024+1), nil, 413, nil)
	send("DELETE", "/v1/sessions/current?x-iwut-session=secret", "", nil, 400, nil)
	send("DELETE", "/v1/sessions/current", `{"sessionToken":"secret"}`, nil, 400, nil)
	send("DELETE", "/v1/sessions/current", "", nil, 400, nil)
	send("DELETE", "/v1/sessions/current", "", http.Header{"X-Iwut-Session": {registered.Session.SessionToken, registered.Session.SessionToken}}, 400, nil)
	// Exercise generated HTTP client, including standard ProtoJSON bytes mapping.
	transport, err := khttp.NewClient(t.Context(), khttp.WithEndpoint(base))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	generated := authv1.NewAuthenticationServiceHTTPClient(transport)
	loginChallenge, err := generated.BeginDeviceLogin(t.Context(), &authv1.BeginDeviceLoginRequest{CredentialLocator: &authv1.BeginDeviceLoginRequest_CredentialId{CredentialId: registered.CredentialId}})
	if err != nil {
		t.Fatal(err)
	}
	var login authv1.SessionEstablished
	send("POST", "/v1/device-logins/"+loginChallenge.OperationId+"/completion", encode(&authv1.CompleteDeviceLoginRequest{Proof: &authv1.CredentialProof{Signature: signDevice(t, key, loginChallenge.SigningPayload)}}), nil, 201, &login)
	if login.AuthId != registered.AuthId || login.SessionToken == registered.Session.SessionToken {
		t.Fatal("HTTP login mismatch")
	}
	for i := 0; i < 2; i++ {
		send("DELETE", "/v1/sessions/current", "", session, 200, nil)
	}
	credentialPath := "/v1/users/me/credentials/" + registered.CredentialId
	send("DELETE", credentialPath, "", session, 401, nil)
	send("DELETE", credentialPath, "", identity, 401, nil)
	// Every non-current ID is rejected before a target ownership lookup.
	otherPath := "/v1/users/me/credentials/" + uuid.NewString()
	denied := send("DELETE", otherPath, "", http.Header{"X-Iwut-Session": {login.SessionToken}}, 403, nil)
	if !bytes.Contains(denied, []byte("CREDENTIAL_REAUTH_REQUIRED")) {
		t.Fatal("non-current target did not require dedicated reauthentication")
	}
	send("DELETE", credentialPath, "", http.Header{"X-Iwut-Session": {login.SessionToken}}, 200, nil)
	send("DELETE", credentialPath, "", http.Header{"X-Iwut-Session": {login.SessionToken}}, 401, nil)
	loginChallenge, err = generated.BeginDeviceLogin(t.Context(), &authv1.BeginDeviceLoginRequest{CredentialLocator: &authv1.BeginDeviceLoginRequest_CredentialId{CredentialId: registered.CredentialId}})
	if err != nil {
		t.Fatal(err)
	}
	send("POST", "/v1/device-logins/"+loginChallenge.OperationId+"/completion", encode(&authv1.CompleteDeviceLoginRequest{Proof: &authv1.CredentialProof{Signature: signDevice(t, key, loginChallenge.SigningPayload)}}), nil, 401, nil)
	for _, path := range []string{"/auth_center.v1.identity.UserIdentityService/IssueUserIdentityFromSession", "/v1/identities", "/v1/scope-catalog", "/auth-center/v1/registrations"} {
		send("POST", path, `{}`, nil, 404, nil)
	}
	// Numeric ProtoJSON int64 output is represented as a JSON string.
	var jsonResult map[string]any
	if err := json.Unmarshal(send("GET", "/v1/users/me/profile", "", identity, 200, nil), &jsonResult); err != nil {
		t.Fatal(err)
	}
	if jsonResult["revision"] != "2" {
		t.Fatalf("nonstandard ProtoJSON revision: %v", jsonResult["revision"])
	}
}
