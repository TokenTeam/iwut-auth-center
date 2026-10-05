package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	apppb "github.com/TokenTeam/iwut-api-proto/gen/go/app_center/v1/application"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_management"
	statuspb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_status"
	profilepb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"iwut-auth-center/internal/config"
	"net/http"
	"strings"
	"testing"
	"time"
)

func runDeveloperManagementFlow(t *testing.T, env map[string]string, conn *grpc.ClientConn, user *authpb.UserRegistrationResult, issue func(string) string, keyFile string, serviceKey *rsa.PrivateKey) string {
	t.Helper()
	client := pb.NewDeveloperManagementServiceClient(conn)
	ordinary := issue("iwut-auth-center")
	userContext := func(token string) context.Context {
		return metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", token))
	}
	query := &pb.GetManagedDeveloperStatusRequest{SubjectAuthId: user.AuthId}
	if _, e := client.GetManagedDeveloperStatus(userContext(ordinary), query); status.Code(e) != codes.PermissionDenied {
		t.Fatal(e)
	}
	if _, e := client.GetManagedDeveloperStatus(t.Context(), query); status.Code(e) != codes.Unauthenticated {
		t.Fatal(e)
	}
	for _, key := range []string{config.MongoURIEnv, config.MongoDatabaseEnv, "AUTH_EMAIL_LOGIN_ENABLED", "AUTH_EMAIL_RECOVERY_READY"} {
		t.Setenv(key, env[key])
	}
	var output bytes.Buffer
	if e := bootstrapPlatformAdmin([]string{"--auth-id", user.AuthId}, &output); e != nil {
		t.Fatal(e)
	}
	adminToken := issue("iwut-auth-center")
	ctx := userContext(adminToken)
	state, e := client.GetManagedDeveloperStatus(ctx, query)
	if e != nil || state.DeveloperRevision != 1 || state.DeveloperStatus != pb.DeveloperStatus_APPROVED {
		t.Fatal(state, e)
	}
	appConn, _, _ := startActualApp(t, env[config.MongoURIEnv], keyFile, env[config.GRPCAddrEnv], serviceKey)
	app := apppb.NewApplicationClient(appConn)
	oldAppToken := issue("iwut-app-center")
	transport, e := khttp.NewClient(t.Context(), khttp.WithEndpoint("http://"+env[config.HTTPAddrEnv]), khttp.WithTimeout(5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	defer transport.Close()
	httpClient := pb.NewDeveloperManagementServiceHTTPClient(transport)
	headers := http.Header{"X-Iwut-Identity": []string{adminToken}}
	paused, e := httpClient.ManageDeveloperStatus(t.Context(), &pb.ManageDeveloperStatusRequest{SubjectAuthId: user.AuthId, Action: pb.Action_SUSPEND, ExpectedDeveloperRevision: proto.Int64(1), Reason: "governance check"}, khttp.Header(&headers))
	if e != nil || paused.DeveloperStatus != pb.DeveloperStatus_SUSPENDED || paused.DeveloperRevision != 2 {
		t.Fatal(paused, e)
	}
	directory := statuspb.NewDeveloperStatusDirectoryClient(conn)
	statuses, e := directory.BatchGetDeveloperStatuses(serviceCallContext(t, t.Context(), serviceKey, "app-center", "app-center-2026-01", "iwut-auth-center"), &statuspb.BatchGetDeveloperStatusesRequest{AuthIds: []string{user.AuthId}})
	if e != nil || statuses.Entries[0].DeveloperStatus != statuspb.DeveloperStatus_DEVELOPER_STATUS_SUSPENDED {
		t.Fatal(statuses, e)
	}
	current := issue("iwut-app-center")
	if identityPayload(t, current)["developer_status"] != "SUSPENDED" {
		t.Fatal("stale status")
	}
	if _, e = app.CreateApplication(userContext(current), &apppb.CreateApplicationRequest{Name: "Suspended_App"}); status.Code(e) != codes.PermissionDenied {
		t.Fatal("actual App allowed suspended writes", e)
	}
	// Offline consumers retain the documented short-JWS window.
	if _, e = app.CreateApplication(userContext(oldAppToken), &apppb.CreateApplicationRequest{Name: "Old_JWS_Window"}); e != nil {
		t.Fatal("unexpected old JWS semantics", e)
	}
	if _, e = profilepb.NewUserProfileServiceClient(conn).GetOwnProfile(userContext(issue("iwut-auth-center")), &profilepb.GetOwnProfileRequest{}); e != nil {
		t.Fatal("ordinary session/profile revoked", e)
	}
	if _, e = client.ManageDeveloperStatus(ctx, &pb.ManageDeveloperStatusRequest{SubjectAuthId: user.AuthId, Action: pb.Action_SUSPEND, ExpectedDeveloperRevision: proto.Int64(1), Reason: "stale retry"}); status.Code(e) != codes.Aborted {
		t.Fatal(e)
	}
	restored, e := client.ManageDeveloperStatus(ctx, &pb.ManageDeveloperStatusRequest{SubjectAuthId: user.AuthId, Action: pb.Action_RESTORE, ExpectedDeveloperRevision: proto.Int64(2), Reason: "recovery"})
	if e != nil || restored.DeveloperStatus != pb.DeveloperStatus_APPROVED || restored.DeveloperRevision != 3 {
		t.Fatal(restored, e)
	}
	if _, e = app.CreateApplication(userContext(issue("iwut-app-center")), &apppb.CreateApplicationRequest{Name: "Restored_App"}); status.Code(e) != codes.ResourceExhausted {
		t.Fatal("restored App does not pass developer gate", e)
	}
	for _, body := range []string{`{"subjectAuthId":"x","unknown":true}`, `{"subjectAuthId":"x","subjectAuthId":"y"}`} {
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "http://"+env[config.HTTPAddrEnv]+"/v1/developers:get-managed-status", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-iwut-identity", adminToken)
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 400 || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal(res.StatusCode)
		}
	}
	return adminToken
}
func runDeveloperManagementRecoveryClosed(t *testing.T, conn *grpc.ClientConn, authID, identity string) {
	t.Helper()
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", identity))
	client := pb.NewDeveloperManagementServiceClient(conn)
	if _, e := client.ManageDeveloperStatus(ctx, &pb.ManageDeveloperStatusRequest{SubjectAuthId: authID, Action: pb.Action_SUSPEND, ExpectedDeveloperRevision: proto.Int64(3), Reason: "no recovery deployment"}); e != nil {
		t.Fatal(e)
	}
	if _, e := client.ManageDeveloperStatus(ctx, &pb.ManageDeveloperStatusRequest{SubjectAuthId: authID, Action: pb.Action_RESTORE, ExpectedDeveloperRevision: proto.Int64(4), Reason: "blocked"}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal(e)
	}
}
