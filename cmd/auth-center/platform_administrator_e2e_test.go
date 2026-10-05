package main

import (
	"bytes"
	"encoding/json"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/platform_administrator"
	reviewpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/reviewer_permission"
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

func runPlatformAdministratorFlow(t *testing.T, env map[string]string, conn *grpc.ClientConn, admin, subject *authpb.UserRegistrationResult, issue func(*authpb.UserRegistrationResult, string) string, bind func(*authpb.UserRegistrationResult, string)) {
	client := pb.NewPlatformAdministratorServiceClient(conn)
	oldToken := issue(admin, "iwut-auth-center")
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", oldToken))
	query := &pb.GetPlatformAdministratorRequest{SubjectAuthId: subject.AuthId}
	for _, tc := range []struct {
		token string
		want  codes.Code
	}{{"", codes.Unauthenticated}, {issue(subject, "iwut-auth-center"), codes.PermissionDenied}, {issue(admin, "iwut-app-center"), codes.Unauthenticated}} {
		c := t.Context()
		if tc.token != "" {
			c = metadata.NewOutgoingContext(c, metadata.Pairs("x-iwut-identity", tc.token))
		}
		_, err := client.GetPlatformAdministrator(c, query)
		if status.Code(err) != tc.want {
			t.Fatal(err, tc.want)
		}
	}
	observed, err := client.GetPlatformAdministrator(ctx, query)
	if err != nil || observed.Membership != pb.Membership_NONE || len(observed.GrantBlockers) != 1 || observed.GrantBlockers[0] != pb.GrantBlocker_EMAIL_REQUIRED {
		t.Fatal(observed, err)
	}
	grant := &pb.ManagePlatformAdministratorRequest{SubjectAuthId: subject.AuthId, Action: pb.Action_GRANT, ExpectedPermissionRevision: proto.Int64(observed.PermissionRevision), Reason: "  platform onboarding  "}
	if _, err = client.ManagePlatformAdministrator(ctx, grant); status.Code(err) != codes.FailedPrecondition {
		t.Fatal(err)
	}
	bind(subject, "second-admin@example.test")
	httpTransport, err := khttp.NewClient(t.Context(), khttp.WithEndpoint("http://"+env[config.HTTPAddrEnv]), khttp.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer httpTransport.Close()
	httpClient := pb.NewPlatformAdministratorServiceHTTPClient(httpTransport)
	authHeader := func() khttp.CallOption {
		headers := http.Header{"X-Iwut-Identity": []string{oldToken}}
		return khttp.Header(&headers)
	}
	granted, err := httpClient.ManagePlatformAdministrator(t.Context(), grant, authHeader())
	if err != nil || !granted.Effective || granted.PermissionRevision != observed.PermissionRevision+1 {
		t.Fatal(granted, err)
	}
	list, err := httpClient.ListPlatformAdministrators(t.Context(), &pb.ListPlatformAdministratorsRequest{PageSize: proto.Int32(1)}, authHeader())
	if err != nil || len(list.Items) != 1 || list.NextAfterAuthId == "" {
		t.Fatal(list, err)
	}
	list, err = client.ListPlatformAdministrators(ctx, &pb.ListPlatformAdministratorsRequest{AfterAuthId: list.NextAfterAuthId})
	if err != nil || len(list.Items) != 1 || list.NextAfterAuthId != "" {
		t.Fatal(list, err)
	}
	for _, body := range []string{`{"pageSize":0}`, `{"pageSize":1,"pageSize":2}`, `{"unknown":1}`} {
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "http://"+env[config.HTTPAddrEnv]+"/v1/platform-administrators:list", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-iwut-identity", oldToken)
		response, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 400 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal(response.StatusCode, string(data))
		}
	}
	self, err := client.GetPlatformAdministrator(ctx, &pb.GetPlatformAdministratorRequest{SubjectAuthId: admin.AuthId})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := client.ManagePlatformAdministrator(ctx, &pb.ManagePlatformAdministratorRequest{SubjectAuthId: admin.AuthId, Action: pb.Action_REVOKE, ExpectedPermissionRevision: proto.Int64(self.PermissionRevision), Reason: "handover"})
	if err != nil || revoked.Effective || revoked.Membership != pb.Membership_NONE {
		t.Fatal(revoked, err)
	}
	for _, call := range []func() error{func() error { _, e := client.GetPlatformAdministrator(ctx, query); return e }, func() error { _, e := client.ManagePlatformAdministrator(ctx, grant); return e }, func() error {
		_, e := reviewpb.NewReviewerPermissionServiceClient(conn).GetApplicationReviewPermissions(ctx, &reviewpb.GetApplicationReviewPermissionsRequest{SubjectAuthId: subject.AuthId})
		return e
	}} {
		if e := call(); status.Code(e) != codes.PermissionDenied {
			t.Fatal("revoked old JWS", e)
		}
	}
	fresh := identityPayload(t, issue(admin, "iwut-auth-center"))
	if len(fresh["permissions"].([]any)) != 0 {
		t.Fatal(fresh)
	}
	if p := identityPayload(t, issue(subject, "iwut-auth-center")); len(p["permissions"].([]any)) != 4 {
		t.Fatal(p)
	}
	if p := identityPayload(t, issue(subject, "iwut-app-center")); len(p["permissions"].([]any)) != 0 {
		t.Fatal(p)
	}
	secondCtx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", issue(subject, "iwut-auth-center")))
	if _, e := client.ManagePlatformAdministrator(secondCtx, &pb.ManagePlatformAdministratorRequest{SubjectAuthId: subject.AuthId, Action: pb.Action_REVOKE, ExpectedPermissionRevision: proto.Int64(granted.PermissionRevision), Reason: "last"}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal(e)
	}
	var output bytes.Buffer
	if e := bootstrapPlatformAdmin([]string{"--auth-id", admin.AuthId}, &output); e != nil {
		t.Fatal(e)
	}
	var result struct {
		Applied bool
		EventID string
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Applied || result.EventID == "" {
		t.Fatal(output.String())
	}
	if p := identityPayload(t, issue(admin, "iwut-auth-center")); len(p["permissions"].([]any)) != 0 {
		t.Fatal("bootstrap resurrected", p)
	}
}
