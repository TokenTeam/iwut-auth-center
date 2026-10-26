package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/scope_management"
	"github.com/go-kratos/kratos/v2/middleware"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	d "iwut-auth-center/internal/scopemanagement/domain"
	"iwut-auth-center/internal/scopemanagement/usecase"
)

type scopeManagementRepositoryStub struct {
	snapshot  d.Snapshot
	command   d.Command
	operation d.Operation
	err       error
}

func (r *scopeManagementRepositoryStub) Get(context.Context, string) (d.Snapshot, error) {
	return r.snapshot, r.err
}
func (r *scopeManagementRepositoryStub) Change(_ context.Context, c d.Command) (d.Operation, error) {
	r.command = c
	return r.operation, r.err
}
func (r *scopeManagementRepositoryStub) Operation(context.Context, string, string) (d.Operation, error) {
	return r.operation, r.err
}

type scopeManagementLimiterStub bool

func (l scopeManagementLimiterStub) AllowBegin(string, time.Time) bool    { return bool(l) }
func (l scopeManagementLimiterStub) AllowComplete(string, time.Time) bool { return bool(l) }

func validScopeChangeRequest() *pb.ChangeScopeCatalogRequest {
	revision := int64(1)
	enabled := false
	return &pb.ChangeScopeCatalogRequest{OperationId: "11111111-1111-4111-8111-111111111111", ExpectedRevision: &revision, ExpectedDigest: strings.Repeat("a", 64), Reason: " maintenance ", Changes: []*pb.ScopeChange{{Change: &pb.ScopeChange_SetEnabled{SetEnabled: &pb.SetScopeEnabled{Name: "email", Enabled: &enabled}}}}}
}

func TestScopeManagementTransportPresenceAndConversion(t *testing.T) {
	repo := &scopeManagementRepositoryStub{operation: d.Operation{OperationID: "op", Outcome: "APPLIED", ResultRevision: 2}}
	service := NewScopeManagementService(usecase.New(repo, scopeManagementLimiterStub(true)))
	ctx := context.WithValue(t.Context(), userIdentityContextKey{}, "admin")
	response, err := service.ChangeScopeCatalog(ctx, validScopeChangeRequest())
	if err != nil || response.ResultRevision != 2 || repo.command.ActorAuthID != "admin" || repo.command.Reason != "maintenance" || repo.command.Changes[0].Enabled {
		t.Fatalf("result=%v command=%+v error=%v", response, repo.command, err)
	}
	// Exercise the real UseCase command validator, not a service replacement.
	// REGISTER carries its name only inside Definition; the other command
	// variants carry Name at the change level.
	register := validScopeChangeRequest()
	register.Changes = []*pb.ScopeChange{{Change: &pb.ScopeChange_Register{Register: &pb.RegisterScope{Definition: &pb.RegisterScopeDefinition{Name: "items.read", Label: "Items", Description: "Read items", Kind: "RESOURCE", Audience: "items-service", Enabled: proto.Bool(false)}, Contract: "Read the caller-owned items without side effects", ProviderEvidence: "UC036 provider test"}}}}
	if _, err := service.ChangeScopeCatalog(ctx, register); err != nil || !repo.command.Valid() || repo.command.Changes[0].Name != "" || repo.command.Changes[0].Definition.Name != "items.read" {
		t.Fatalf("register command=%+v error=%v", repo.command, err)
	}
	correct := validScopeChangeRequest()
	correct.Changes = []*pb.ScopeChange{{Change: &pb.ScopeChange_CorrectText{CorrectText: &pb.CorrectScopeText{Name: "email", Label: " Email ", Description: " Verified email "}}}}
	if _, err := service.ChangeScopeCatalog(ctx, correct); err != nil || !repo.command.Valid() || repo.command.Changes[0].Label != "Email" || repo.command.Changes[0].Definition != (d.Definition{}) {
		t.Fatalf("correct-text command=%+v error=%v", repo.command, err)
	}
	for _, mutate := range []func(*pb.ChangeScopeCatalogRequest){func(r *pb.ChangeScopeCatalogRequest) { r.ExpectedRevision = nil }, func(r *pb.ChangeScopeCatalogRequest) { r.Changes = nil }, func(r *pb.ChangeScopeCatalogRequest) { r.Changes[0] = nil }, func(r *pb.ChangeScopeCatalogRequest) { r.Changes[0].GetSetEnabled().Enabled = nil }, func(r *pb.ChangeScopeCatalogRequest) { r.Changes[0].ProtoReflect().SetUnknown([]byte{0x78, 1}) }} {
		r := validScopeChangeRequest()
		mutate(r)
		if _, err := service.ChangeScopeCatalog(ctx, r); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("accepted malformed request: %v", err)
		}
	}
	if _, err := service.GetManagedScopeCatalog(t.Context(), &pb.GetManagedScopeCatalogRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
}

func TestScopeManagementHTTPStrictShapeAndNoStore(t *testing.T) {
	identity := func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			return next(context.WithValue(ctx, userIdentityContextKey{}, "admin"), req)
		}
	}
	repo := &scopeManagementRepositoryStub{snapshot: d.Snapshot{Revision: 1, GeneratedAt: time.Now().UTC(), Digest: strings.Repeat("a", 64)}}
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0", UserEndpoints: &UserEndpoints{ProfileIdentity: identity, ScopeManagement: NewScopeManagementService(usecase.New(repo, scopeManagementLimiterStub(true))), MaxAuthenticationMessageBytes: 16384}}, nil)
	for _, test := range []struct {
		body string
		code int
	}{{`{}`, 200}, {`null`, 400}, {`{"unknown":"secret"}`, 400}, {`{"unknown":null}`, 400}, {`{"x":1,"x":2}`, 400}, {strings.Repeat(" ", scopeManagementMessageLimit+1), 413}} {
		req := httptest.NewRequest("POST", "/v1/scope-catalog:get", strings.NewReader(test.body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != test.code || rec.Header().Get("Cache-Control") != "no-store" || strings.Contains(rec.Body.String(), "secret") {
			t.Fatalf("body=%q got=%d %s", test.body[:min(len(test.body), 80)], rec.Code, rec.Body)
		}
	}
	for _, test := range []struct {
		suffix, encoding, contentType string
		code                          int
	}{{"?x=1", "", "application/json", 400}, {"", "gzip", "application/json", 415}, {"", "", "text/plain", 415}} {
		req := httptest.NewRequest("POST", "/v1/scope-catalog:get"+test.suffix, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", test.contentType)
		req.Header.Set("Content-Encoding", test.encoding)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != test.code {
			t.Fatalf("got=%d want=%d", rec.Code, test.code)
		}
	}
	rec := httptest.NewRecorder()
	newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0"}, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/scope-catalog:get", strings.NewReader(`{}`)))
	if rec.Code != 404 {
		t.Fatal("disabled route registered")
	}
}

func TestScopeManagementCodecRejectsDuplicateOneofAndMalformedBoolean(t *testing.T) {
	request := validScopeChangeRequest()
	wire, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if !scopeManagementWire(wire, &pb.ChangeScopeCatalogRequest{}) {
		t.Fatal("valid repeated wire rejected")
	}
	request.Changes = append(request.Changes, request.Changes[0])
	wire, _ = proto.Marshal(request)
	if !scopeManagementWire(wire, &pb.ChangeScopeCatalogRequest{}) {
		t.Fatal("repeated changes rejected")
	}
	for _, wire := range [][]byte{{0x12, 1, 0x12, 2}, {0x10, 2}, {0x28, 1}, {0x78, 1}} {
		if strictScopeManagementWire(wire, (&pb.SetScopeEnabled{}).ProtoReflect().Descriptor()) {
			t.Fatalf("accepted wire %x", wire)
		}
	}
	branch := protowire.AppendBytes(protowire.AppendTag(nil, 3, protowire.BytesType), []byte{0x10, 0})
	branch = append(branch, branch...)
	if strictScopeManagementWire(branch, (&pb.ScopeChange{}).ProtoReflect().Descriptor()) {
		t.Fatal("duplicate oneof accepted")
	}
	codec := NewProfileStrictCodec()
	message := &pb.ChangeScopeCatalogRequest{}
	if err := codec.Unmarshal([]byte{0x78, 1}, message); err != nil || validScopeManagementMessage(message) {
		t.Fatalf("codec rejection lost: %v", err)
	}
}

func TestScopeManagementExactAuthenticationDispatch(t *testing.T) {
	called := false
	profile := func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, r any) (any, error) { called = true; return next(ctx, r) }
	}
	h := userEndpointAuthenticationMiddleware(nil, profile, nil, true)(func(context.Context, any) (any, error) { return nil, nil })
	for _, method := range []string{pb.ScopeManagementService_GetManagedScopeCatalog_FullMethodName, pb.ScopeManagementService_ChangeScopeCatalog_FullMethodName, pb.ScopeManagementService_GetScopeCatalogOperation_FullMethodName} {
		called = false
		if _, err := h(kt.NewServerContext(t.Context(), dispatchTransport{method}), &pb.GetManagedScopeCatalogRequest{}); err != nil || !called {
			t.Fatalf("method=%s err=%v", method, err)
		}
	}
	called = false
	_, err := h(kt.NewServerContext(t.Context(), dispatchTransport{pb.ScopeManagementService_ChangeScopeCatalog_FullMethodName + "/extra"}), &pb.GetManagedScopeCatalogRequest{})
	if status.Code(err) != codes.PermissionDenied || called {
		t.Fatal("nonexact method gained user auth")
	}
}

func TestScopeManagementErrorCodes(t *testing.T) {
	for _, test := range []struct {
		err  error
		code codes.Code
	}{{d.ErrForbidden, codes.PermissionDenied}, {d.ErrConflict, codes.Aborted}, {d.ErrOperationConflict, codes.Aborted}, {d.ErrNotFound, codes.NotFound}, {d.ErrBlocked, codes.FailedPrecondition}, {d.ErrRevisionExhausted, codes.FailedPrecondition}, {d.ErrRate, codes.ResourceExhausted}, {context.DeadlineExceeded, codes.Unavailable}} {
		if actual := status.Code(scopeManagementError(test.err)); actual != test.code {
			t.Fatalf("%v got=%v want=%v", test.err, actual, test.code)
		}
	}
}
