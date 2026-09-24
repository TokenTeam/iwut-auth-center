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
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	identitypb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/identity"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/reviewer_permission"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"io"
	"iwut-auth-center/internal/config"
	"net/http"
	"strings"
	"testing"
)

func runReviewerFlow(t *testing.T, env map[string]string, conn *grpc.ClientConn, serviceKey *rsa.PrivateKey) {
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
	// A modified payload cannot manufacture management authority.
	pieces := strings.Split(ordinary, ".")
	pieces[1] = strings.Split(token, ".")[1]
	if _, err = review.GetReviewerPermission(userctx(strings.Join(pieces, ".")), &pb.GetReviewerPermissionRequest{SubjectAuthId: subject.AuthId}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
}
