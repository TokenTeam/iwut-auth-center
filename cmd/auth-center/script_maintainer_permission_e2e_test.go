package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	legacy "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/script_maintainer_permission"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/script_permission"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"iwut-auth-center/internal/config"
)

func runScriptPermissionFlow(t *testing.T, env map[string]string, conn *grpc.ClientConn, appURL string, subject *authpb.UserRegistrationResult, adminctx context.Context, adminToken string, issue func(*authpb.UserRegistrationResult, string) string) {
	t.Helper()
	client := pb.NewScriptPermissionServiceClient(conn)
	legacyClient := legacy.NewScriptMaintainerPermissionServiceClient(conn)
	query := &pb.GetScriptPermissionsRequest{SubjectAuthId: subject.AuthId}
	legacyQuery := &legacy.GetScriptMaintainerPermissionRequest{SubjectAuthId: subject.AuthId}
	httpTransport, err := khttp.NewClient(t.Context(), khttp.WithEndpoint("http://"+env[config.HTTPAddrEnv]), khttp.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer httpTransport.Close()
	httpClient := pb.NewScriptPermissionServiceHTTPClient(httpTransport)
	authHeader := func() khttp.CallOption {
		header := http.Header{"X-Iwut-Identity": []string{adminToken}}
		return khttp.Header(&header)
	}

	ordinary := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", issue(subject, "iwut-auth-center")))
	if _, err := client.GetScriptPermissions(ordinary, query); status.Code(err) != codes.PermissionDenied {
		t.Fatal("ordinary user can query script grants", err)
	}
	if _, err := client.GetScriptPermissions(t.Context(), query); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	appID, _ := uuid.NewV7()
	versionID, _ := uuid.NewV7()
	reviewID, _ := uuid.NewV7()
	appPath := fmt.Sprintf("%s/v1/applications/%s/versions/%s/reviews/%s/decision", appURL, appID, versionID, reviewID)
	checkApp := func(identity string, want int) {
		t.Helper()
		body := strings.NewReader(`{"outcome":"REJECT","expectedPolicyVersion":"app-version-review-v2","reason":"script permission isolation"}`)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, appPath, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Iwut-Identity", identity)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode != want {
			t.Fatalf("real App verifier/capability gate: got %d want %d", response.StatusCode, want)
		}
	}
	permissions := []struct {
		id   string
		code pb.ScriptPermission
	}{
		{"app.script.maintain", pb.ScriptPermission_SCRIPT_PERMISSION_MAINTAIN},
		{"app.script.review", pb.ScriptPermission_SCRIPT_PERMISSION_REVIEW},
		{"app.script.publish", pb.ScriptPermission_SCRIPT_PERMISSION_PUBLISH},
		{"app.script.suspend", pb.ScriptPermission_SCRIPT_PERMISSION_SUSPEND},
		{"app.script.restore", pb.ScriptPermission_SCRIPT_PERMISSION_RESTORE},
	}
	granted := map[pb.ScriptPermission]bool{}
	revision := int64(9)
	seenJTI := map[string]bool{}
	checkSnapshot := func(state *pb.ScriptPermissions, err error) {
		t.Helper()
		if err != nil || state.GetSubjectAuthId() != subject.AuthId || state.GetPermissionRevision() != revision || len(state.GetPermissions()) != len(permissions) {
			t.Fatalf("expected five states at revision %d: %v, %v", revision, state, err)
		}
		for i, permission := range permissions {
			item := state.Permissions[i]
			if item.GetPermission() != permission.code || item.GetGranted() != granted[permission.code] || item.GetEffective() != granted[permission.code] {
				t.Fatalf("revision %d permission %s: %v", revision, permission.id, item)
			}
		}
	}
	check := func() {
		t.Helper()
		checkSnapshot(httpClient.GetScriptPermissions(t.Context(), query, authHeader()))
		maintain, err := legacyClient.GetScriptMaintainerPermission(adminctx, legacyQuery)
		expected := granted[pb.ScriptPermission_SCRIPT_PERMISSION_MAINTAIN]
		if err != nil || maintain.GetSubjectAuthId() != subject.AuthId || maintain.GetPermissionRevision() != revision || maintain.GetGranted() != expected || maintain.GetEffective() != expected {
			t.Fatal("legacy query diverged", maintain, err)
		}

		token := issue(subject, "iwut-app-center")
		payload := identityPayload(t, token)
		jti, ok := payload["jti"].(string)
		want := []string{}
		for _, permission := range permissions {
			if granted[permission.code] {
				want = append(want, permission.id)
			}
		}
		slices.Sort(want)
		claim, array := payload["permissions"].([]any)
		if payload["sub"] != subject.AuthId || payload["aud"] != "iwut-app-center" || !ok || jti == "" || seenJTI[jti] || !array ||
			!slices.EqualFunc(claim, want, func(a any, b string) bool { return a == b }) {
			t.Fatalf("revision %d expected App permissions %v: %v", revision, want, payload)
		}
		seenJTI[jti] = true
		checkApp(token, http.StatusForbidden) // Real App verifier accepted this identity; it does not have the App Reviewer permission.
		authToken := issue(subject, "iwut-auth-center")
		if len(identityPayload(t, authToken)["permissions"].([]any)) != 0 {
			t.Fatal("Auth audience disclosed script permissions")
		}
		if len(want) == len(permissions) {
			checkApp(authToken, http.StatusUnauthorized)
			wrongAudience := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", token))
			if _, err := client.GetScriptPermissions(wrongAudience, query); status.Code(err) != codes.Unauthenticated {
				t.Fatal("App audience accessed Auth permission query", err)
			}
			scriptOperator := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", authToken))
			req := &pb.ManageScriptPermissionRequest{SubjectAuthId: subject.AuthId, Permission: pb.ScriptPermission_SCRIPT_PERMISSION_REVIEW,
				Action: pb.ScriptPermissionAction_SCRIPT_PERMISSION_ACTION_REVOKE, ExpectedPermissionRevision: proto.Int64(revision), Reason: "unauthorized"}
			if _, err := client.ManageScriptPermission(scriptOperator, req); status.Code(err) != codes.PermissionDenied {
				t.Fatal("script permissions granted administrator authority", err)
			}
		}
	}

	check()
	for _, malformed := range []struct {
		selector pb.ScriptPermission
		wire     uint64
	}{
		{pb.ScriptPermission_SCRIPT_PERMISSION_MAINTAIN, 2},
		{pb.ScriptPermission_SCRIPT_PERMISSION_UNSPECIFIED, 1<<32 | 1},
		{pb.ScriptPermission_SCRIPT_PERMISSION_UNSPECIFIED, 0},
	} {
		req := &pb.ManageScriptPermissionRequest{SubjectAuthId: subject.AuthId, Permission: malformed.selector,
			Action: pb.ScriptPermissionAction_SCRIPT_PERMISSION_ACTION_GRANT, ExpectedPermissionRevision: proto.Int64(revision), Reason: "invalid selector"}
		req.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 2, protowire.VarintType), malformed.wire))
		if _, err := client.ManageScriptPermission(adminctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatal("duplicate/overflowing/unspecified wire enum accepted", malformed, err)
		}
	}
	for _, permission := range permissions {
		request := &pb.ManageScriptPermissionRequest{SubjectAuthId: subject.AuthId, Permission: permission.code,
			Action: pb.ScriptPermissionAction_SCRIPT_PERMISSION_ACTION_GRANT, ExpectedPermissionRevision: proto.Int64(revision), Reason: "  script duty  "}
		state, err := httpClient.ManageScriptPermission(t.Context(), request, authHeader())
		granted[permission.code] = true
		revision++
		checkSnapshot(state, err)
		check()
	}
	for _, permission := range permissions {
		expected := revision
		revision++
		delete(granted, permission.code)
		if permission.code == pb.ScriptPermission_SCRIPT_PERMISSION_MAINTAIN {
			state, err := legacyClient.ManageScriptMaintainerPermission(adminctx, &legacy.ManageScriptMaintainerPermissionRequest{
				SubjectAuthId: subject.AuthId, Action: legacy.ScriptMaintainerPermissionAction_SCRIPT_MAINTAINER_PERMISSION_ACTION_REVOKE,
				ExpectedPermissionRevision: proto.Int64(expected), Reason: "legacy revoke",
			})
			if err != nil || state.GetGranted() || state.GetEffective() || state.GetPermissionRevision() != revision {
				t.Fatal("legacy revoke did not update shared state", state, err)
			}
		} else {
			state, err := client.ManageScriptPermission(adminctx, &pb.ManageScriptPermissionRequest{
				SubjectAuthId: subject.AuthId, Permission: permission.code, Action: pb.ScriptPermissionAction_SCRIPT_PERMISSION_ACTION_REVOKE,
				ExpectedPermissionRevision: proto.Int64(expected), Reason: "end of script duty",
			})
			checkSnapshot(state, err)
		}
		check()
	}
	t.Log("UC038: five exact grants and revocations, shared legacy maintain state, fresh same-Session App JWS and real App verifier")
}
