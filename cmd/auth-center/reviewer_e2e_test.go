package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	emailpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	identitypb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/identity"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/reviewer_permission"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"io"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/testutil/smtpcapture"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func runReviewerFlow(t *testing.T, env map[string]string, conn *grpc.ClientConn, serviceKey *rsa.PrivateKey, keyFile string, capture *smtpcapture.Server) {
	t.Helper()
	auth := authpb.NewAuthenticationServiceClient(conn)
	issuer := identitypb.NewUserIdentityServiceClient(conn)
	review := pb.NewReviewerPermissionServiceClient(conn)
	register := func(label string) *authpb.UserRegistrationResult {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		token := sha256.Sum256([]byte(label))
		u, _ := registerUser(t, auth, key, token[:])
		return u
	}
	admin, subject := register("reviewer-admin"), register("reviewer-subject")
	bindEmail := func(user *authpb.UserRegistrationResult, email string) {
		t.Helper()
		client := emailpb.NewEmailBindingServiceClient(conn)
		ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-session", user.Session.SessionToken))
		challenge, err := client.BeginSetEmail(ctx, &emailpb.BeginSetEmailRequest{RequestId: uuid.NewString(), Email: email, Intent: &emailpb.BeginSetEmailRequest_Binding{Binding: &emailpb.BindEmailIntent{ExpectedRevision: proto.Int64(0)}}})
		if err != nil {
			t.Fatal(err)
		}
		match := regexp.MustCompile(`Verification code: ([0-9]{8})`).FindStringSubmatch(capture.Next(t).Body)
		if len(match) != 2 {
			t.Fatal("missing code")
		}
		if _, err = client.CompleteSetEmail(ctx, &emailpb.CompleteSetEmailRequest{OperationId: challenge.OperationId, Code: match[1]}); err != nil {
			t.Fatal(err)
		}
	}
	bindEmail(admin, "administrator@example.test")
	issue := func(user *authpb.UserRegistrationResult, aud string) string {
		ctx := metadata.AppendToOutgoingContext(serviceCallContext(t, t.Context(), serviceKey, "gateway", "app-center-2026-01", "iwut-auth-center"), "x-iwut-session", user.Session.SessionToken)
		result, err := issuer.IssueUserIdentityFromSession(ctx, &identitypb.IssueUserIdentityFromSessionRequest{Audience: aud})
		if err != nil {
			t.Fatal(err)
		}
		return result.IdentityJws
	}
	userctx := func(token string) context.Context {
		return metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", token))
	}
	ordinary := issue(admin, "iwut-auth-center")
	if _, err := review.GetReviewerPermission(userctx(ordinary), &pb.GetReviewerPermissionRequest{SubjectAuthId: subject.AuthId}); status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
	if _, err := review.GetReviewerPermission(t.Context(), &pb.GetReviewerPermissionRequest{SubjectAuthId: subject.AuthId}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	t.Setenv(config.MongoURIEnv, env[config.MongoURIEnv])
	t.Setenv(config.MongoDatabaseEnv, env[config.MongoDatabaseEnv])
	t.Setenv("AUTH_EMAIL_RECOVERY_READY", "true")
	t.Setenv("AUTH_EMAIL_LOGIN_ENABLED", "true")
	var output bytes.Buffer
	if err := bootstrapPlatformAdmin([]string{"--auth-id", admin.AuthId}, &output); err != nil {
		t.Fatal(err)
	}
	var result struct{ Applied bool }
	if json.Unmarshal(output.Bytes(), &result) != nil || !result.Applied {
		t.Fatal(output.String())
	}
	token := issue(admin, "iwut-auth-center")
	adminctx := userctx(token)
	// Administrator capability does not imply App reviewer capability.
	if p := identityPayload(t, issue(admin, "iwut-app-center")); len(p["permissions"].([]any)) != 0 {
		t.Fatal(p)
	}
	request := &pb.ManageReviewerPermissionRequest{SubjectAuthId: subject.AuthId, Action: pb.ReviewerPermissionAction_REVIEWER_PERMISSION_ACTION_GRANT, ExpectedRevision: proto.Int64(1), Reason: "  onboarding  "}
	granted, err := review.ManageReviewerPermission(adminctx, request)
	if err != nil || !granted.Reviewer || granted.PermissionRevision != 2 {
		t.Fatal(granted, err)
	}
	oldToken := issue(subject, "iwut-app-center")
	if p := identityPayload(t, oldToken); len(p["permissions"].([]any)) != 1 || p["permissions"].([]any)[0] != "app.version.review" {
		t.Fatal(p)
	}
	client := &http.Client{}
	defer client.CloseIdleConnections()
	path := "http://" + env[config.HTTPAddrEnv] + "/v1/users/" + subject.AuthId + "/reviewer-permission"
	send := func(method, body, identity string, want int) {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if identity != "" {
			req.Header.Set("x-iwut-identity", identity)
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			t.Fatalf("HTTP %d want %d: %s", res.StatusCode, want, data)
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("cache")
		}
	}
	send("GET", "", token, 200)
	send("GET", "", ordinary, 403)
	send("PUT", `{"action":2,"expectedRevision":"2","reason":"done","unknown":true}`, token, 400)
	send("PUT", `{"action":2,"expectedRevision":"2","reason":"done","reason":"duplicate"}`, token, 400)
	send("PUT", `{"action":2,"expectedRevision":"2","reason":"done"}`, token, 200)
	if p := identityPayload(t, issue(subject, "iwut-app-center")); len(p["permissions"].([]any)) != 0 {
		t.Fatal(p)
	}
	if p := identityPayload(t, oldToken); len(p["permissions"].([]any)) != 1 {
		t.Fatal("old signed token changed")
	}
	current, err := review.GetReviewerPermission(adminctx, &pb.GetReviewerPermissionRequest{SubjectAuthId: subject.AuthId})
	if err != nil || current.Reviewer || current.PermissionRevision != 3 {
		t.Fatal(current, err)
	}
	runApplicationReviewFlow(t, env, conn, serviceKey, keyFile, subject, adminctx, token, issue)
	runPlatformAdministratorFlow(t, env, conn, admin, subject, issue, bindEmail)
	// A modified payload cannot manufacture management authority.
	pieces := strings.Split(ordinary, ".")
	pieces[1] = strings.Split(token, ".")[1]
	if _, err = review.GetReviewerPermission(userctx(strings.Join(pieces, ".")), &pb.GetReviewerPermissionRequest{SubjectAuthId: subject.AuthId}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
}

// Cross-service acceptance uses Auth's real signer and the sibling App's real
// verifier and review handlers. Missing review IDs deliberately stop at 404
// after the capability gate, without manufacturing an App review fixture.
func runApplicationReviewFlow(t *testing.T, env map[string]string, conn *grpc.ClientConn, serviceKey *rsa.PrivateKey, keyFile string, subject *authpb.UserRegistrationResult, adminctx context.Context, adminToken string, issue func(*authpb.UserRegistrationResult, string) string) {
	t.Helper()
	_, appURL, _ := startActualApp(t, env[config.MongoURIEnv], keyFile, env[config.GRPCAddrEnv], serviceKey)
	client := pb.NewReviewerPermissionServiceClient(conn)
	transport, err := khttp.NewClient(t.Context(), khttp.WithEndpoint("http://"+env[config.HTTPAddrEnv]), khttp.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	httpClient := pb.NewReviewerPermissionServiceHTTPClient(transport)
	authHeader := func() khttp.CallOption {
		headers := http.Header{"X-Iwut-Identity": []string{adminToken}}
		return khttp.Header(&headers)
	}
	const profile, version = "app.profile.review", "app.version.review"
	query := &pb.GetApplicationReviewPermissionsRequest{SubjectAuthId: subject.AuthId}
	check := func(wantProfile, wantVersion bool, revision int64) {
		t.Helper()
		result, err := httpClient.GetApplicationReviewPermissions(t.Context(), query, authHeader())
		if err != nil || result.SubjectAuthId != subject.AuthId || result.PermissionRevision != revision || len(result.Permissions) != 2 {
			t.Fatal("generated combined query", result, err)
		}
		if result.Permissions[0].Permission != profile || result.Permissions[0].Granted != wantProfile || result.Permissions[1].Permission != version || result.Permissions[1].Granted != wantVersion {
			t.Fatal(result)
		}
		old, err := httpClient.GetReviewerPermission(t.Context(), &pb.GetReviewerPermissionRequest{SubjectAuthId: subject.AuthId}, authHeader())
		if err != nil || old.Reviewer != wantVersion || old.PermissionRevision != revision {
			t.Fatal("generated legacy query", old, err)
		}
		token := issue(subject, "iwut-app-center")
		wanted := []any{}
		if wantProfile {
			wanted = append(wanted, profile)
		}
		if wantVersion {
			wanted = append(wanted, version)
		}
		payload := identityPayload(t, token)
		if !slices.Equal(payload["permissions"].([]any), wanted) || payload["developer_status"] != nil {
			t.Fatal(payload)
		}
		if payload := identityPayload(t, issue(subject, "iwut-auth-center")); len(payload["permissions"].([]any)) != 0 {
			t.Fatal(payload)
		}
		appID, _ := uuid.NewV7()
		revisionID, _ := uuid.NewV7()
		reviewID, _ := uuid.NewV7()
		for _, tc := range []struct {
			path, body string
			allowed    bool
		}{
			{fmt.Sprintf("/v1/applications/%s/profile-revisions/%s/reviews/%s/decision", appID, revisionID, reviewID), `{"outcome":"REJECT","expectedProfileRevisionRevision":"1","expectedPolicyVersion":"app-profile-review-v1","reason":"capability boundary test"}`, wantProfile},
			{fmt.Sprintf("/v1/applications/%s/versions/%s/reviews/%s/decision", appID, revisionID, reviewID), `{"outcome":"REJECT","expectedPolicyVersion":"app-version-review-v2","reason":"capability boundary test"}`, wantVersion},
		} {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, appURL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("x-iwut-identity", token)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(res.Body)
			res.Body.Close()
			want := 403
			if tc.allowed {
				want = 404
			}
			if res.StatusCode != want {
				t.Fatalf("actual App %s: %d want %d: %s", tc.path, res.StatusCode, want, data)
			}
		}
	}
	check(false, false, 3)

	// Strict decoding must remain identical on the new route. None of these
	// malformed calls may mutate revision 3 or select an implicit permission.
	base := "http://" + env[config.HTTPAddrEnv] + "/v1/users/" + subject.AuthId
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/application-review-permissions?permission=app.profile.review", ""},
		{"GET", "/application-review-permissions", `{}`},
		{"PUT", "/application-review-permissions/" + profile, `{"action":1,"reason":"missing revision"}`},
		{"PUT", "/application-review-permissions/" + profile, `{"action":1,"expectedRevision":"3","reason":"x","unknown":true}`},
		{"PUT", "/application-review-permissions/" + profile, `{"action":1,"expectedRevision":"3","reason":"x","reason":"duplicate"}`},
		{"PUT", "/reviewer-permission", `{"action":1,"expectedRevision":"3","reason":"x","permission":"app.profile.review"}`},
	} {
		req, err := http.NewRequestWithContext(t.Context(), tc.method, base+tc.path, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-iwut-identity", adminToken)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 400 || !bytes.Contains(data, []byte("INVALID_REVIEWER_PERMISSION_INPUT")) {
			t.Fatal(tc.path, response.StatusCode, string(data))
		}
	}
	unknown := &pb.ManageApplicationReviewPermissionRequest{SubjectAuthId: subject.AuthId, Permission: profile, Action: pb.ReviewerPermissionAction_REVIEWER_PERMISSION_ACTION_GRANT, ExpectedRevision: proto.Int64(3), Reason: "unknown"}
	unknown.ProtoReflect().SetUnknown([]byte{0x32, 1, 'x'})
	if _, err := client.ManageApplicationReviewPermission(adminctx, unknown); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	for _, bad := range []string{"", " app.profile.review", "app.*", "APP.PROFILE.REVIEW", "auth.reviewer.manage", "openid"} {
		_, err := client.ManageApplicationReviewPermission(adminctx, &pb.ManageApplicationReviewPermissionRequest{SubjectAuthId: subject.AuthId, Permission: bad, Action: pb.ReviewerPermissionAction_REVIEWER_PERMISSION_ACTION_GRANT, ExpectedRevision: proto.Int64(3), Reason: "invalid target"})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatal(bad, err)
		}
	}
	if _, err := client.GetApplicationReviewPermissions(t.Context(), query); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	ordinary := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", issue(subject, "iwut-auth-center")))
	if _, err := client.GetApplicationReviewPermissions(ordinary, query); status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
	request := &pb.ManageApplicationReviewPermissionRequest{SubjectAuthId: subject.AuthId, Permission: profile, Action: pb.ReviewerPermissionAction_REVIEWER_PERMISSION_ACTION_GRANT, ExpectedRevision: proto.Int64(3), Reason: "profile reviewer"}
	result, err := httpClient.ManageApplicationReviewPermission(t.Context(), request, authHeader())
	if err != nil || result.PermissionRevision != 4 {
		t.Fatal("generated explicit grant", result, err)
	}
	check(true, false, 4)
	if _, err := client.ManageApplicationReviewPermission(adminctx, request); status.Code(err) != codes.Aborted {
		t.Fatal(err)
	}
	// Legacy GRANT/REVOKE must preserve the independent profile permission.
	old := &pb.ManageReviewerPermissionRequest{SubjectAuthId: subject.AuthId, Action: pb.ReviewerPermissionAction_REVIEWER_PERMISSION_ACTION_GRANT, ExpectedRevision: proto.Int64(4), Reason: "version reviewer"}
	if _, err := client.ManageReviewerPermission(adminctx, old); err != nil {
		t.Fatal(err)
	}
	check(true, true, 5)
	old.Action = pb.ReviewerPermissionAction_REVIEWER_PERMISSION_ACTION_REVOKE
	old.ExpectedRevision = proto.Int64(5)
	if _, err := client.ManageReviewerPermission(adminctx, old); err != nil {
		t.Fatal(err)
	}
	check(true, false, 6)
	old.Action = pb.ReviewerPermissionAction_REVIEWER_PERMISSION_ACTION_GRANT
	old.ExpectedRevision = proto.Int64(6)
	if _, err := client.ManageReviewerPermission(adminctx, old); err != nil {
		t.Fatal(err)
	}
	request.Action = pb.ReviewerPermissionAction_REVIEWER_PERMISSION_ACTION_REVOKE
	request.ExpectedRevision = proto.Int64(7)
	if _, err := client.ManageApplicationReviewPermission(adminctx, request); err != nil {
		t.Fatal(err)
	}
	check(false, true, 8)
	request.Permission = version
	request.ExpectedRevision = proto.Int64(8)
	if _, err := client.ManageApplicationReviewPermission(adminctx, request); err != nil {
		t.Fatal(err)
	}
	check(false, false, 9)
	t.Log("Actual Auth grants and signer -> actual App verifier and both review handlers: independent permissions, legacy compatibility, revocation")
}
