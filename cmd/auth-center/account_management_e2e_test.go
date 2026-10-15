package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_management"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	adminpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/platform_administrator"
	reviewpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/reviewer_permission"
	profilepb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
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
	"time"
)

func runAccountManagementFlow(t *testing.T, env map[string]string, conn *grpc.ClientConn, admin *authpb.UserRegistrationResult, issue func(*authpb.UserRegistrationResult, string) string, bind func(*authpb.UserRegistrationResult, string)) {
	t.Helper()
	client := pb.NewAccountManagementServiceClient(conn)
	auth := authpb.NewAuthenticationServiceClient(conn)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	association := sha256.Sum256([]byte("account-lifecycle"))
	user, _ := registerUser(t, conn, key, association[:])
	adminToken := issue(admin, "iwut-auth-center")
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", adminToken))
	userToken := issue(user, "iwut-auth-center")
	oldUserCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", userToken))
	query := &pb.GetUserAccountStatusRequest{SubjectAuthId: user.AuthId}
	for _, c := range []context.Context{t.Context(), oldUserCtx} {
		_, err := client.GetUserAccountStatus(c, query)
		want := codes.PermissionDenied
		if c == t.Context() {
			want = codes.Unauthenticated
		}
		if status.Code(err) != want {
			t.Fatal(err, want)
		}
	}
	state, err := client.GetUserAccountStatus(ctx, query)
	if err != nil || state.AccountRevision != 1 || state.StatusChangedAt != nil {
		t.Fatal(state, err)
	}
	if _, err = client.ManageUserAccountStatus(ctx, &pb.ManageUserAccountStatusRequest{SubjectAuthId: admin.AuthId, Action: pb.AccountStatusAction_ACCOUNT_STATUS_ACTION_DISABLE, ExpectedAccountRevision: proto.Int64(1), Reason: "last admin"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("last administrator disabled", err)
	}
	bind(user, "managed-admin@example.test")
	admins := adminpb.NewPlatformAdministratorServiceClient(conn)
	if _, err := admins.ManagePlatformAdministrator(ctx, &adminpb.ManagePlatformAdministratorRequest{SubjectAuthId: user.AuthId, Action: adminpb.Action_GRANT, ExpectedPermissionRevision: proto.Int64(1), Reason: "test old administrator generation"}); err != nil {
		t.Fatal(err)
	}
	oldAdminCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", issue(user, "iwut-auth-center")))
	pending, err := auth.BeginDeviceLogin(t.Context(), &authpb.BeginDeviceLoginRequest{CredentialLocator: &authpb.BeginDeviceLoginRequest_CredentialId{CredentialId: user.CredentialId}})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := client.ManageUserAccountStatus(ctx, &pb.ManageUserAccountStatusRequest{SubjectAuthId: user.AuthId, Action: pb.AccountStatusAction_ACCOUNT_STATUS_ACTION_DISABLE, ExpectedAccountRevision: proto.Int64(1), Reason: " investigation "})
	if err != nil || disabled.AccountRevision != 2 || disabled.AccountStatus != pb.AccountStatus_ACCOUNT_STATUS_DISABLED {
		t.Fatal(disabled, err)
	}
	httpTransport, err := khttp.NewClient(t.Context(), khttp.WithEndpoint("http://"+env[config.HTTPAddrEnv]), khttp.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer httpTransport.Close()
	httpClient := pb.NewAccountManagementServiceHTTPClient(httpTransport)
	headers := http.Header{"X-Iwut-Identity": []string{adminToken}}
	restored, err := httpClient.ManageUserAccountStatus(t.Context(), &pb.ManageUserAccountStatusRequest{SubjectAuthId: user.AuthId, Action: pb.AccountStatusAction_ACCOUNT_STATUS_ACTION_RESTORE, ExpectedAccountRevision: proto.Int64(2), Reason: "resolved"}, khttp.Header(&headers))
	if err != nil || restored.AccountRevision != 3 || restored.AccountStatus != pb.AccountStatus_ACCOUNT_STATUS_ACTIVE {
		t.Fatal(restored, err)
	}
	if _, err = auth.CompleteDeviceLogin(t.Context(), &authpb.CompleteDeviceLoginRequest{OperationId: pending.OperationId, Proof: &authpb.CredentialProof{Signature: signDevice(t, key, pending.SigningPayload)}}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("old challenge revived", err)
	}
	if _, err = profilepb.NewUserProfileServiceClient(conn).GetOwnProfile(oldUserCtx, &profilepb.GetOwnProfileRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("old JWS revived", err)
	}
	if _, err := admins.GetPlatformAdministrator(oldAdminCtx, &adminpb.GetPlatformAdministratorRequest{SubjectAuthId: admin.AuthId}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("old admin generation", err)
	}
	if _, err := reviewpb.NewReviewerPermissionServiceClient(conn).GetApplicationReviewPermissions(oldAdminCtx, &reviewpb.GetApplicationReviewPermissionsRequest{SubjectAuthId: user.AuthId}); status.Code(err) != codes.Unauthenticated {
		t.Fatal("old reviewer-manager generation", err)
	}
	if _, err := admins.ManagePlatformAdministrator(ctx, &adminpb.ManagePlatformAdministratorRequest{SubjectAuthId: user.AuthId, Action: adminpb.Action_REVOKE, ExpectedPermissionRevision: proto.Int64(2), Reason: "end generation test"}); err != nil {
		t.Fatal(err)
	}
	fresh := loginUser(t, auth, key, user.CredentialId)
	user.Session = fresh
	freshToken := issue(user, "iwut-auth-center")
	if identityPayload(t, freshToken)["account_revision"] != "3" {
		t.Fatal("fresh account generation missing")
	}
	freshCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", freshToken))
	if _, err = profilepb.NewUserProfileServiceClient(conn).GetOwnProfile(freshCtx, &profilepb.GetOwnProfileRequest{}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"subjectAuthId":"x","unknown":1}`, `{"subjectAuthId":"x","subjectAuthId":"y"}`} {
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "http://"+env[config.HTTPAddrEnv]+"/v1/user-accounts:get-status", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-iwut-identity", adminToken)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 400 || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal(res.StatusCode, string(data))
		}
	}
}
