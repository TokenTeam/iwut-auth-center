package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/scope_management"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
)

var errScopeManagementResponseLost = errors.New("injected scope management response loss")

// scopeManagementResponseLossTransport injects a lost response at the caller
// boundary only. It sends the real request, completely consumes and closes the
// real 200 response, then hides it from the caller. It neither changes Mongo
// behavior nor retains/logs the response body or the trusted identity.
type scopeManagementResponseLossTransport struct {
	upstream          http.RoundTripper
	completedResponse bool
}

func (transport *scopeManagementResponseLossTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.upstream.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusOK {
		return response, err
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	transport.completedResponse = true
	return nil, errScopeManagementResponseLost
}

// The caller provisions both identities through the production registration and
// administrator bootstrap paths. This helper never writes Catalog directly.
func runScopeManagementWireFlow(t *testing.T, configuration config.Config, db *mongo.Database, conn *grpc.ClientConn, adminToken, normalToken string) {
	t.Helper()
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", adminToken))
	normal := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-identity", normalToken))
	client := pb.NewScopeManagementServiceClient(conn)
	for _, denied := range []struct {
		tokenContext bool
		want         codes.Code
	}{{false, codes.Unauthenticated}, {true, codes.PermissionDenied}} {
		requestContext := t.Context()
		if denied.tokenContext {
			requestContext = normal
		}
		if _, err := client.GetManagedScopeCatalog(requestContext, &pb.GetManagedScopeCatalogRequest{}); status.Code(err) != denied.want {
			t.Fatalf("scope read auth=%v: %v", denied.tokenContext, err)
		}
	}
	initial, err := client.GetManagedScopeCatalog(ctx, &pb.GetManagedScopeCatalogRequest{})
	if err != nil || initial.Revision < 1 || len(initial.Digest) != 64 {
		t.Fatalf("managed catalog=%v,%v", initial, err)
	}
	emailEnabled := false
	for _, definition := range initial.Scopes {
		if definition.Name == "email" {
			emailEnabled = definition.Enabled
		}
	}
	if !emailEnabled {
		t.Fatal("fixture must provide enabled email scope")
	}
	baseURL := "http://" + configuration.HTTPAddr
	httpTransport, err := khttp.NewClient(t.Context(), khttp.WithEndpoint(baseURL), khttp.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer httpTransport.Close()
	httpClient := pb.NewScopeManagementServiceHTTPClient(httpTransport)
	authHeader := func() khttp.CallOption {
		headers := http.Header{"X-Iwut-Identity": []string{adminToken}}
		return khttp.Header(&headers)
	}
	viaHTTP, err := httpClient.GetManagedScopeCatalog(t.Context(), &pb.GetManagedScopeCatalogRequest{}, authHeader())
	if err != nil || !proto.Equal(initial, viaHTTP) {
		t.Fatalf("HTTP/gRPC catalog mismatch: %v,%v", viaHTTP, err)
	}
	makeChange := func(snapshot *pb.ManagedScopeCatalog, enabled bool) *pb.ChangeScopeCatalogRequest {
		return &pb.ChangeScopeCatalogRequest{OperationId: uuid.NewString(), ExpectedRevision: proto.Int64(snapshot.Revision), ExpectedDigest: snapshot.Digest, Reason: "UC036 isolated Wire lifecycle acceptance", Changes: []*pb.ScopeChange{{Change: &pb.ScopeChange_SetEnabled{SetEnabled: &pb.SetScopeEnabled{Name: "email", Enabled: proto.Bool(enabled)}}}}}
	}
	command := makeChange(initial, false)
	for _, mutate := range []func(*pb.ChangeScopeCatalogRequest){func(r *pb.ChangeScopeCatalogRequest) { r.ExpectedRevision = nil }, func(r *pb.ChangeScopeCatalogRequest) { r.Changes[0].GetSetEnabled().Enabled = nil }, func(r *pb.ChangeScopeCatalogRequest) { r.Changes[0] = nil }} {
		invalid := proto.Clone(command).(*pb.ChangeScopeCatalogRequest)
		mutate(invalid)
		if _, err := client.ChangeScopeCatalog(ctx, invalid); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid scope change accepted: %v", err)
		}
	}
	for _, test := range []struct {
		path, body, encoding, contentType string
		code                              int
	}{
		{"/v1/scope-catalog:get", `null`, "", "application/json", 400},
		{"/v1/scope-catalog:get", `{"unknown":"secret"}`, "", "application/json", 400},
		{"/v1/scope-catalog:change", `{"changes":[null]}`, "", "application/json", 400},
		{"/v1/scope-catalog:change", `{"changes":[{"setEnabled":{"name":"email","enabled":null}}]}`, "", "application/json", 400},
		{"/v1/scope-catalog:change", `{"changes":[{"setEnabled":{"name":"email","enabled":false,"enabled":true}}]}`, "", "application/json", 400},
		{"/v1/scope-catalog:get?x=1", `{}`, "", "application/json", 400},
		{"/v1/scope-catalog:get", `{}`, "gzip", "application/json", 415},
		{"/v1/scope-catalog:get", `{}`, "", "text/plain", 415},
		{"/v1/scope-catalog:get", strings.Repeat(" ", 128*1024+1), "", "application/json", 413},
	} {
		req, err := http.NewRequestWithContext(t.Context(), "POST", baseURL+test.path, strings.NewReader(test.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("x-iwut-identity", adminToken)
		req.Header.Set("Content-Type", test.contentType)
		req.Header.Set("Content-Encoding", test.encoding)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != test.code || response.Header.Get("Cache-Control") != "no-store" || strings.Contains(string(body), "secret") {
			t.Fatalf("strict %s got %d %s want=%d", test.path, response.StatusCode, body, test.code)
		}
	}
	beforeAudits, err := db.Collection(ma.ScopeManagementAuditCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ChangeScopeCatalog(normal, command); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("nonadmin change=%v", err)
	}
	result, err := httpClient.ChangeScopeCatalog(t.Context(), command, authHeader())
	if err != nil || result.Outcome != "APPLIED" || result.ResultRevision != initial.Revision+1 {
		t.Fatalf("disable result=%v,%v", result, err)
	}
	queried, err := client.GetScopeCatalogOperation(ctx, &pb.GetScopeCatalogOperationRequest{OperationId: command.OperationId})
	if err != nil || !proto.Equal(result, queried) {
		t.Fatalf("operation query=%v,%v", queried, err)
	}
	if _, err := client.GetScopeCatalogOperation(normal, &pb.GetScopeCatalogOperationRequest{OperationId: command.OperationId}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("nonadmin operation=%v", err)
	}
	replayed, err := client.ChangeScopeCatalog(ctx, command)
	if err != nil || !proto.Equal(result, replayed) {
		t.Fatalf("idempotent replay=%v,%v", replayed, err)
	}
	modified := proto.Clone(command).(*pb.ChangeScopeCatalogRequest)
	modified.Reason = "different reason"
	if _, err := client.ChangeScopeCatalog(ctx, modified); status.Code(err) != codes.Aborted {
		t.Fatalf("ID mismatch=%v", err)
	}
	stale := proto.Clone(command).(*pb.ChangeScopeCatalogRequest)
	stale.OperationId = uuid.NewString()
	if _, err := client.ChangeScopeCatalog(ctx, stale); status.Code(err) != codes.Aborted {
		t.Fatalf("stale no-op=%v", err)
	}
	disabled, err := client.GetManagedScopeCatalog(ctx, &pb.GetManagedScopeCatalogRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range disabled.Scopes {
		if scope.Name == "email" && scope.Enabled {
			t.Fatal("email not disabled")
		}
	}
	// Reassemble the actual composition runtime against the same database. Its
	// old manifest still says enabled, but startup must not overwrite live state.
	runtime, cleanup, err := provideOAuth(configuration, db, &transport.UserEndpoints{})
	if err != nil {
		t.Fatal("rebuild after management", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	if runtime == nil {
		t.Fatal("missing rebuilt runtime")
	}
	afterRestart, err := client.GetManagedScopeCatalog(ctx, &pb.GetManagedScopeCatalogRequest{})
	if err != nil || !proto.Equal(disabled, afterRestart) {
		t.Fatalf("startup overwrote live catalog=%v,%v", afterRestart, err)
	}
	count, err := db.Collection(ma.ScopeManagementAuditCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil || count != beforeAudits+1 {
		t.Fatalf("replay/startup changed audit count=%d before=%d err=%v", count, beforeAudits, err)
	}
	restored, err := client.ChangeScopeCatalog(ctx, makeChange(disabled, true))
	if err != nil || restored.ResultRevision != result.ResultRevision+1 {
		t.Fatalf("restore=%v,%v", restored, err)
	}
	noOpSnapshot, err := client.GetManagedScopeCatalog(ctx, &pb.GetManagedScopeCatalogRequest{})
	if err != nil {
		t.Fatal(err)
	}
	noOp, err := client.ChangeScopeCatalog(ctx, makeChange(noOpSnapshot, true))
	if err != nil || noOp.Outcome != "NO_CHANGE" || noOp.ResultRevision != restored.ResultRevision {
		t.Fatalf("no-op=%v,%v", noOp, err)
	}
	viaHTTPReceipt, err := httpClient.GetScopeCatalogOperation(t.Context(), &pb.GetScopeCatalogOperationRequest{OperationId: noOp.OperationId}, authHeader())
	if err != nil || !proto.Equal(noOp, viaHTTPReceipt) {
		t.Fatalf("HTTP receipt=%v,%v", viaHTTPReceipt, err)
	}

	// A successful Mongo commit and a response lost to its caller are distinct
	// from the repository's commit-failure injection. Recover through normal
	// generated APIs using the original operation identifier, without inferring
	// whether the first request failed from its synthetic network error.
	lostCommand := makeChange(noOpSnapshot, false)
	body, err := protojson.Marshal(lostCommand)
	if err != nil {
		t.Fatal(err)
	}
	beforeLossAudits, err := db.Collection(ma.ScopeManagementAuditCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/v1/scope-catalog:change", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-iwut-identity", adminToken)
	loss := &scopeManagementResponseLossTransport{upstream: http.DefaultTransport}
	lossClient := &http.Client{Transport: loss, Timeout: 5 * time.Second}
	if _, err := lossClient.Do(request); !errors.Is(err, errScopeManagementResponseLost) || !loss.completedResponse {
		t.Fatal("response-loss boundary did not observe and hide a completed 200 response")
	}
	recovered, err := httpClient.GetScopeCatalogOperation(t.Context(), &pb.GetScopeCatalogOperationRequest{OperationId: lostCommand.OperationId}, authHeader())
	if err != nil || recovered.Outcome != "APPLIED" || recovered.ResultRevision != noOpSnapshot.Revision+1 {
		t.Fatalf("lost-response receipt recovery=%v,%v", recovered, err)
	}
	afterLoss, err := client.GetManagedScopeCatalog(ctx, &pb.GetManagedScopeCatalogRequest{})
	if err != nil || afterLoss.Revision != recovered.ResultRevision || afterLoss.Digest != recovered.ResultDigest {
		t.Fatalf("lost-response catalog recovery=%v,%v", afterLoss, err)
	}
	replayedLoss, err := client.ChangeScopeCatalog(ctx, lostCommand)
	if err != nil || !proto.Equal(recovered, replayedLoss) {
		t.Fatalf("lost-response original-ID replay=%v,%v", replayedLoss, err)
	}
	afterReplay, err := client.GetManagedScopeCatalog(ctx, &pb.GetManagedScopeCatalogRequest{})
	if err != nil || !proto.Equal(afterLoss, afterReplay) {
		t.Fatalf("lost-response replay changed catalog=%v,%v", afterReplay, err)
	}
	afterLossAudits, err := db.Collection(ma.ScopeManagementAuditCollection).CountDocuments(t.Context(), bson.M{})
	if err != nil || afterLossAudits != beforeLossAudits+1 {
		t.Fatalf("lost-response replay changed audit count=%d before=%d err=%v", afterLossAudits, beforeLossAudits, err)
	}
	if restore, err := client.ChangeScopeCatalog(ctx, makeChange(afterLoss, true)); err != nil || restore.ResultRevision != recovered.ResultRevision+1 {
		t.Fatalf("restore after response-loss acceptance=%v,%v", restore, err)
	}
}
