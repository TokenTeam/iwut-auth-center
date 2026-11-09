package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	appopspb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_operations_permission"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	emailpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/managed_user_search"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"iwut-auth-center/internal/config"
)

func runManagedUserSearchAndApplicationSearchFlow(t *testing.T, env map[string]string, conn *grpc.ClientConn, appURL string, subject *authpb.UserRegistrationResult, adminctx context.Context, adminToken string, issue func(*authpb.UserRegistrationResult, string) string) {
	t.Helper()
	client := pb.NewManagedUserSearchServiceClient(conn)
	query := &pb.SearchUsersRequest{Selector: &pb.SearchUsersRequest_AuthId{AuthId: subject.AuthId}}
	ordinary := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", issue(subject, "iwut-auth-center")))
	if _, err := client.SearchUsers(ordinary, query); status.Code(err) != codes.PermissionDenied {
		t.Fatal("ordinary user search", err)
	}
	if _, err := client.SearchUsers(t.Context(), query); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	binding, err := emailpb.NewEmailBindingServiceClient(conn).GetOwnEmailBinding(sessionCallContext(t.Context(), subject.Session.SessionToken), &emailpb.GetOwnEmailBindingRequest{})
	if err != nil || binding.GetActiveEmail() == nil {
		t.Fatal(binding, err)
	}
	transport, err := khttp.NewClient(t.Context(), khttp.WithEndpoint("http://"+env[config.HTTPAddrEnv]), khttp.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	httpClient := pb.NewManagedUserSearchServiceHTTPClient(transport)
	header := func() khttp.CallOption {
		h := http.Header{"X-Iwut-Identity": []string{adminToken}}
		return khttp.Header(&h)
	}
	for _, selector := range []*pb.SearchUsersRequest{
		query,
		{Selector: &pb.SearchUsersRequest_Email{Email: " " + strings.ToUpper(binding.ActiveEmail.Email) + " "}},
	} {
		result, err := httpClient.SearchUsers(t.Context(), selector, header())
		if err != nil || len(result.GetItems()) != 1 || result.Items[0].AuthId != subject.AuthId || result.Items[0].DeveloperStatus != nil || result.AsOf.CheckValid() != nil {
			t.Fatal("minimal real user lookup", result, err)
		}
	}
	for _, req := range []*pb.SearchUsersRequest{{}, {Selector: &pb.SearchUsersRequest_Email{Email: "not-an-email"}}} {
		if _, err := client.SearchUsers(adminctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatal(req, err)
		}
	}
	duplicate := proto.Clone(query).(*pb.SearchUsersRequest)
	duplicate.ProtoReflect().SetUnknown(protowire.AppendString(protowire.AppendTag(nil, 2, protowire.BytesType), binding.ActiveEmail.Email))
	if _, err := client.SearchUsers(adminctx, duplicate); status.Code(err) != codes.InvalidArgument {
		t.Fatal("dual oneof accepted", err)
	}
	for _, input := range []struct {
		suffix, body string
		code         int
	}{
		{"", `{"authId":"` + subject.AuthId + `","email":"` + binding.ActiveEmail.Email + `"}`, 400},
		{"", `{"authId":null,"email":"` + binding.ActiveEmail.Email + `"}`, 400},
		{"", `{"authId":"` + subject.AuthId + `","auth_id":"other"}`, 400},
		{"", `{"email":"` + binding.ActiveEmail.Email + `","actorAuthId":"spoofed"}`, 400},
		{"?email=hidden", `{}`, 400},
		{"", `{"email":"` + strings.Repeat("x", 16384) + `"}`, 413},
		{"", `{"authId":"not-a-user"}`, 200},
	} {
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+env[config.HTTPAddrEnv]+"/v1/managed-users:search"+input.suffix, strings.NewReader(input.body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Iwut-Identity", adminToken)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != input.code || response.Header.Get("Cache-Control") != "private, no-store" {
			t.Fatal(response.StatusCode, string(body), response.Header)
		}
		if input.code == 200 {
			var value map[string]any
			if json.Unmarshal(body, &value) != nil {
				t.Fatal(string(body))
			}
			items, ok := value["items"].([]any)
			if !ok || len(items) != 0 {
				t.Fatal("empty set omitted", string(body))
			}
		}
	}

	operations := appopspb.NewApplicationOperationsPermissionServiceClient(conn)
	ownQuery := &appopspb.GetOwnApplicationOperationsPermissionsRequest{}
	state, err := operations.GetOwnApplicationOperationsPermissions(ordinary, ownQuery)
	if err != nil || len(state.EffectivePermissions) != 0 {
		t.Fatal(state, err)
	}
	revision := state.PermissionRevision
	seen := map[string]bool{}
	for step := range 3 {
		if step > 0 {
			action := appopspb.ApplicationOperationsPermissionAction_APPLICATION_OPERATIONS_PERMISSION_ACTION_GRANT
			if step == 2 {
				action = appopspb.ApplicationOperationsPermissionAction_APPLICATION_OPERATIONS_PERMISSION_ACTION_REVOKE
			}
			updated, err := operations.ManageApplicationOperationsPermission(adminctx, &appopspb.ManageApplicationOperationsPermissionRequest{SubjectAuthId: subject.AuthId, Permission: "app.application.search", Action: action, ExpectedPermissionRevision: proto.Int64(revision), Reason: "application directory discovery"})
			if err != nil {
				t.Fatal(updated, err)
			}
			revision++
			if updated.PermissionRevision != revision || len(updated.Permissions) != 3 {
				t.Fatal(updated)
			}
		}
		own, err := operations.GetOwnApplicationOperationsPermissions(ordinary, ownQuery)
		want := []string{}
		if step == 1 {
			want = []string{"app.application.search"}
		}
		if err != nil || own.PermissionRevision != revision || !slices.Equal(own.EffectivePermissions, want) {
			t.Fatal(own, err)
		}
		token := issue(subject, "iwut-app-center")
		payload := identityPayload(t, token)
		jti, _ := payload["jti"].(string)
		if payload["sub"] != subject.AuthId || jti == "" || seen[jti] || !slices.EqualFunc(payload["permissions"].([]any), want, func(a any, b string) bool { return a == b }) {
			t.Fatal(payload)
		}
		seen[jti] = true
		if len(identityPayload(t, issue(subject, "iwut-auth-center"))["permissions"].([]any)) != 0 {
			t.Fatal("search disclosed to Auth audience")
		}
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, appURL+"/v1/applications/01995000-0000-7000-8000-000000000001/versions/01995000-0000-7000-8000-000000000002/reviews/01995000-0000-7000-8000-000000000003/decision", strings.NewReader(`{"outcome":"REJECT","expectedPolicyVersion":"app-version-review-v2","reason":"search permission isolation"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Iwut-Identity", token)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("real App verifier/capability gate", response.StatusCode)
		}
	}
	t.Log("UC039 and search: real minimal user lookup, strict HTTP/gRPC, same-Session formal search grant/revoke and own/App identity absent-present-absent")
}
