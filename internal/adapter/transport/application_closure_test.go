package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	closereauthpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_close_reauth"
	closurepb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_closure"
	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	reauthd "iwut-auth-center/internal/applicationclosereauth/domain"
	closured "iwut-auth-center/internal/applicationclosure/domain"
)

type applicationClosureHandlerStub struct {
	applied closured.Tombstone
	caller  string
}

func (h *applicationClosureHandlerStub) Apply(_ context.Context, _, _ string, _ time.Time, caller string) (closured.Tombstone, error) {
	h.caller = caller
	return h.applied, nil
}
func (h *applicationClosureHandlerStub) Get(context.Context, string, string) (closured.Tombstone, error) {
	return h.applied, nil
}

func TestApplicationClosureTransportRequiresExactAppServiceAndPermission(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	h := &applicationClosureHandlerStub{applied: closured.Tombstone{ApplicationID: uuid.NewString(), ClosureID: uuid.NewString(), ReceiptID: uuid.NewString(), AppliedAt: now}}
	service := NewApplicationClosureService(h, "app-center")
	request := &closurepb.ApplyApplicationClosureRequest{ApplicationId: h.applied.ApplicationID, ClosureId: h.applied.ClosureID, ClosingStartedAt: timestamppb.New(now)}
	for _, tc := range []struct {
		name        string
		identity    ServiceIdentity
		want        codes.Code
		wantHandler bool
	}{
		{"allowed", ServiceIdentity{ServiceID: "app-center", permissions: map[string]struct{}{PermissionApplicationClosureApply: {}}}, codes.OK, true},
		{"wrong-service", ServiceIdentity{ServiceID: "other", permissions: map[string]struct{}{PermissionApplicationClosureApply: {}}}, codes.PermissionDenied, false},
		{"wrong-permission", ServiceIdentity{ServiceID: "app-center", permissions: map[string]struct{}{PermissionApplicationClosureRead: {}}}, codes.PermissionDenied, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.caller = ""
			ctx := context.WithValue(t.Context(), serviceIdentityContextKey{}, tc.identity)
			out, err := service.ApplyApplicationClosure(ctx, request)
			if status.Code(err) != tc.want || (h.caller != "") != tc.wantHandler {
				t.Fatalf("out=%v err=%v caller=%q", out, err, h.caller)
			}
			if tc.wantHandler && (out.ReceiptId != h.applied.ReceiptID || h.caller != "app-center") {
				t.Fatalf("out=%v caller=%q", out, h.caller)
			}
		})
	}
	if permission, ok := permissionForOperation(closurepb.ApplicationClosureService_ApplyApplicationClosure_FullMethodName); !ok || permission != PermissionApplicationClosureApply {
		t.Fatalf("Apply permission = %q, %t", permission, ok)
	}
	if _, ok := permissionForOperation(closurepb.ApplicationClosureService_ApplyApplicationClosure_FullMethodName + "/suffix"); ok {
		t.Fatal("non-exact Application closure method was authorized")
	}
}

type closeReauthHandlerStub struct {
	digest []byte
	app    string
}

func (h *closeReauthHandlerStub) Begin(_ context.Context, digest []byte, app string) (reauthd.Challenge, error) {
	h.digest, h.app = append([]byte(nil), digest...), app
	return reauthd.Challenge{OperationID: uuid.NewString(), Challenge: bytes.Repeat([]byte{0x42}, 32), ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}, nil
}
func (h *closeReauthHandlerStub) Complete(context.Context, []byte, string, string, []byte, string, string) (reauthd.Proof, error) {
	return reauthd.Proof{JWS: "header.payload.signature", ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}, nil
}

type closeReauthAdmissionStub struct{ allow bool }

func (a closeReauthAdmissionStub) AllowBegin(string, time.Time) bool   { return a.allow }
func (a closeReauthAdmissionStub) AllowLocator(string, time.Time) bool { return a.allow }

func closeReauthToken() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 32))
}

func TestApplicationCloseReauthHTTPUsesOnlyCanonicalSessionCarrier(t *testing.T) {
	h := &closeReauthHandlerStub{}
	service := NewApplicationCloseReauthService(h, closeReauthAdmissionStub{allow: true}, true)
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0", ApplicationCloseReauth: service}, nil)
	app := uuid.NewString()
	request := httptest.NewRequest("POST", "/v1/application-close-reauth:begin", strings.NewReader(`{"applicationId":"`+app+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-iwut-session", closeReauthToken())
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	wantDigest := sha256.Sum256(bytes.Repeat([]byte{0x21}, 32))
	if recorder.Code != 200 || recorder.Header().Get("Cache-Control") != "no-store" || h.app != app || !bytes.Equal(h.digest, wantDigest[:]) {
		t.Fatalf("status=%d headers=%v body=%s app=%q digest=%x", recorder.Code, recorder.Header(), recorder.Body.String(), h.app, h.digest)
	}

	h.digest = nil
	request = httptest.NewRequest("POST", "/v1/application-close-reauth:begin", strings.NewReader(`{"applicationId":"`+app+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-iwut-session", closeReauthToken())
	request.Header.Set("Authorization", "Bearer user-jws")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != 400 || len(h.digest) != 0 || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("mixed carrier status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestApplicationCloseReauthGRPCMetadataAndErrorMapping(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &closeReauthHandlerStub{}
	service := NewApplicationCloseReauthService(h, closeReauthAdmissionStub{allow: true}, true)
	server := kgrpc.NewServer(kgrpc.Listener(listener), kgrpc.Middleware(userEndpointAuthenticationMiddleware(nil, nil, nil, false)), kgrpc.Options(grpc.ForceServerCodec(NewProfileStrictCodec())))
	closereauthpb.RegisterApplicationCloseReauthServiceServer(server, service)
	done := make(chan error, 1)
	go func() { done <- server.Start(context.Background()) }()
	t.Cleanup(func() { _ = server.Stop(context.Background()); <-done })
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-session", closeReauthToken()))
	var headers metadata.MD
	out, err := closereauthpb.NewApplicationCloseReauthServiceClient(conn).BeginApplicationCloseReauth(ctx, &closereauthpb.BeginApplicationCloseReauthRequest{ApplicationId: uuid.NewString()}, grpc.Header(&headers))
	if err != nil || len(out.Challenge) != 32 || !reflect.DeepEqual(headers.Get("cache-control"), []string{"no-store"}) {
		t.Fatalf("Begin = %v, %v", out, err)
	}
	if status.Code(closeReauthError(t.Context(), reauthd.ErrFailed)) != codes.Unauthenticated || status.Code(closeReauthError(t.Context(), reauthd.ErrInconsistent)) != codes.Internal {
		t.Fatal("close reauth error mapping changed")
	}
}
