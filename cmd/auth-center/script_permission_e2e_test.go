package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/script_permission"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"iwut-auth-center/internal/config"
)

func runScriptPermissionFlow(t *testing.T, env map[string]string, conn *grpc.ClientConn, appURL string, subject *authpb.UserRegistrationResult, adminctx context.Context, adminToken string, issue func(*authpb.UserRegistrationResult, string) string) {
	t.Helper()
	client := pb.NewScriptPermissionServiceClient(conn)
	query := &pb.GetScriptPermissionsRequest{SubjectAuthId: subject.AuthId}
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

	ordinaryToken := issue(subject, "iwut-auth-center")
	ordinary := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", ordinaryToken))
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
			t.Fatalf("expected four states at revision %d: %v, %v", revision, state, err)
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
		checkSnapshot(client.GetOwnScriptPermissions(ordinary, &pb.GetOwnScriptPermissionsRequest{}))
		ownHeader := http.Header{"X-Iwut-Identity": []string{ordinaryToken}}
		checkSnapshot(httpClient.GetOwnScriptPermissions(t.Context(), &pb.GetOwnScriptPermissionsRequest{}, khttp.Header(&ownHeader)))
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
			if _, err := client.GetOwnScriptPermissions(wrongAudience, &pb.GetOwnScriptPermissionsRequest{}); status.Code(err) != codes.Unauthenticated {
				t.Fatal("App audience own-read", err)
			}
			scriptOperator := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", authToken))
			req := &pb.ManageScriptPermissionRequest{SubjectAuthId: subject.AuthId, Permission: pb.ScriptPermission_SCRIPT_PERMISSION_REVIEW,
				Action: pb.ScriptPermissionAction_SCRIPT_PERMISSION_ACTION_REVOKE, ExpectedPermissionRevision: proto.Int64(revision), Reason: "unauthorized"}
			if _, err := client.ManageScriptPermission(scriptOperator, req); status.Code(err) != codes.PermissionDenied {
				t.Fatal("script permissions granted administrator authority", err)
			}
		}
	}

	postRaw := func(path, body string, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+env[config.HTTPAddrEnv]+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Iwut-Identity", adminToken)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s: got HTTP %d, want %d", path, response.StatusCode, want)
		}
	}
	for _, method := range []string{"GetScriptMaintainerPermission", "ManageScriptMaintainerPermission"} {
		const legacyService = "/auth_center.v1.script_maintainer_permission.ScriptMaintainerPermissionService/"
		if err := conn.Invoke(adminctx, legacyService+method, &emptypb.Empty{}, &emptypb.Empty{}); status.Code(err) != codes.Unimplemented {
			t.Fatal("retired RPC", method, err)
		}
	}
	for _, action := range []string{"get", "manage"} {
		postRaw("/v1/script-maintainer-permissions:"+action, `{}`, http.StatusNotFound)
	}
	for _, selector := range []string{`1`, `"SCRIPT_PERMISSION_MAINTAIN"`} {
		body := fmt.Sprintf(`{"subjectAuthId":%q,"permission":%s,"action":1,"expectedPermissionRevision":"%d","reason":"retired enum"}`, subject.AuthId, selector, revision)
		postRaw("/v1/script-permissions:manage", body, http.StatusBadRequest)
	}
	check()
	unknownOwn := &pb.GetOwnScriptPermissionsRequest{}
	unknownOwn.ProtoReflect().SetUnknown(protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "other"))
	if _, err := client.GetOwnScriptPermissions(ordinary, unknownOwn); status.Code(err) != codes.InvalidArgument {
		t.Fatal("own target injection", err)
	}
	if _, err := client.GetOwnScriptPermissions(t.Context(), &pb.GetOwnScriptPermissionsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	for _, input := range []struct {
		suffix, body string
		code         int
	}{
		{"", "", 200}, {"?subjectAuthId=other", "", 400}, {"", `{}`, 400}, {"", `{"subjectAuthId":"other"}`, 400},
	} {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+env[config.HTTPAddrEnv]+"/v1/users/me/script-permissions"+input.suffix, strings.NewReader(input.body))
		req.Header.Set("X-Iwut-Identity", ordinaryToken)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != input.code || response.Header.Get("Cache-Control") != "private, no-store" {
			t.Fatal(response.StatusCode, string(body), response.Header)
		}
		if input.code == 200 {
			var value struct {
				Subject     string           `json:"subjectAuthId"`
				Revision    string           `json:"permissionRevision"`
				Permissions []map[string]any `json:"permissions"`
			}
			if json.Unmarshal(body, &value) != nil || value.Subject != subject.AuthId || value.Revision != "9" || len(value.Permissions) != 4 {
				t.Fatal(string(body))
			}
			for _, item := range value.Permissions {
				grant, ok1 := item["granted"].(bool)
				effective, ok2 := item["effective"].(bool)
				if !ok1 || !ok2 || grant || effective {
					t.Fatal("zero permission flags omitted or invalid", string(body))
				}
			}
		}
	}
	for _, malformed := range []struct {
		selector pb.ScriptPermission
		wire     uint64
	}{
		{pb.ScriptPermission_SCRIPT_PERMISSION_REVIEW, 3},
		{pb.ScriptPermission_SCRIPT_PERMISSION_UNSPECIFIED, 1},
		{pb.ScriptPermission_SCRIPT_PERMISSION_UNSPECIFIED, 1<<32 | 1},
		{pb.ScriptPermission_SCRIPT_PERMISSION_UNSPECIFIED, 0},
	} {
		req := &pb.ManageScriptPermissionRequest{SubjectAuthId: subject.AuthId, Permission: malformed.selector,
			Action: pb.ScriptPermissionAction_SCRIPT_PERMISSION_ACTION_GRANT, ExpectedPermissionRevision: proto.Int64(revision), Reason: "invalid selector"}
		req.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 2, protowire.VarintType), malformed.wire))
		if _, err := client.ManageScriptPermission(adminctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatal("duplicate/overflowing/retired/unspecified wire enum accepted", malformed, err)
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
		state, err := client.ManageScriptPermission(adminctx, &pb.ManageScriptPermissionRequest{
			SubjectAuthId: subject.AuthId, Permission: permission.code, Action: pb.ScriptPermissionAction_SCRIPT_PERMISSION_ACTION_REVOKE,
			ExpectedPermissionRevision: proto.Int64(expected), Reason: "end of script duty",
		})
		checkSnapshot(state, err)
		check()
	}
	t.Log("UC038: four exact grants and revocations, ordinary USER own-read HTTP/gRPC matched every snapshot, retired maintain RPC/HTTP/enum rejected, fresh same-Session App JWS and real App verifier")
}
