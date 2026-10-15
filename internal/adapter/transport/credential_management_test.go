package transport

import (
	"context"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/credential_management"
	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	"net"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type credentialManagementStub struct{ calls int }

func (s *credentialManagementStub) List(context.Context, []byte, int, string) (d.Page, error) {
	s.calls++
	return d.Page{ObservedAt: time.Now(), Credentials: []d.Summary{}}, nil
}
func (*credentialManagementStub) SetLabel(context.Context, []byte, string, string, int64) (d.LabelResult, error) {
	return d.LabelResult{}, nil
}
func (*credentialManagementStub) Begin(context.Context, []byte, string, string) (d.Started, error) {
	return d.Started{}, nil
}
func (*credentialManagementStub) Complete(context.Context, []byte, string, []byte, string, string) error {
	return nil
}

func TestCredentialManagementNativeBoundary(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &credentialManagementStub{}
	gate := &sessionManagementGate{}
	server := kgrpc.NewServer(kgrpc.Listener(listener), kgrpc.Middleware(userEndpointAuthenticationMiddleware(nil, nil, nil, true)), kgrpc.Options(grpc.ForceServerCodec(NewProfileStrictCodec())))
	pb.RegisterCredentialManagementServiceServer(server, NewCredentialManagementService(h, gate))
	done := make(chan error, 1)
	go func() { done <- server.Start(context.Background()) }()
	t.Cleanup(func() { _ = server.Stop(context.Background()); <-done })
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-iwut-session", managementToken(), "x-forwarded-for", "192.0.2.99"))
	for _, tc := range []struct {
		data []byte
		code codes.Code
	}{
		{[]byte{8, 10, 8, 11}, codes.InvalidArgument},
		{[]byte{24, 1}, codes.InvalidArgument},
		{[]byte{18, 3, 'a'}, codes.InvalidArgument},
		{make([]byte, 16385), codes.ResourceExhausted},
	} {
		var headers metadata.MD
		err = conn.Invoke(ctx, pb.CredentialManagementService_ListOwnCredentials_FullMethodName, tc.data, &pb.OwnCredentialPage{}, grpc.ForceCodec(managementRawCodec{encoding.GetCodec("proto")}), grpc.Header(&headers))
		if status.Code(err) != tc.code || !reflect.DeepEqual(headers.Get("cache-control"), []string{"no-store"}) {
			t.Fatal(err, headers)
		}
	}
	client := pb.NewCredentialManagementServiceClient(conn)
	for _, md := range []metadata.MD{
		nil,
		metadata.Pairs("x-iwut-session", managementToken(), "x-iwut-session", managementToken()),
		metadata.Pairs("x-iwut-session", managementToken()+"="),
		metadata.Pairs("x-iwut-session", managementToken(), "authorization", ""),
		metadata.Pairs("x-iwut-session", managementToken(), "cookie", ""),
		metadata.Pairs("x-iwut-session", managementToken(), "x-iwut-identity", ""),
		metadata.Pairs("x-iwut-session", managementToken(), "x-iwut-service-identity", ""),
	} {
		if _, err := client.ListOwnCredentials(metadata.NewOutgoingContext(ctx, md), &pb.ListOwnCredentialsRequest{}); status.Code(err) != codes.Unauthenticated {
			t.Fatal(err)
		}
	}
	if h.calls != 0 {
		t.Fatal("rejected request reached usecase")
	}
	if _, err := client.ListOwnCredentials(ctx, &pb.ListOwnCredentialsRequest{}); err != nil {
		t.Fatal(err)
	}
	_ = server.Stop(context.Background())
	if h.calls != 1 || gate.source != "127.0.0.1" {
		t.Fatal(h.calls, gate.source)
	}
}

func TestCredentialManagementHTTPBoundary(t *testing.T) {
	h := &credentialManagementStub{}
	gate := &sessionManagementGate{}
	server := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0", UserEndpoints: &UserEndpoints{Authentication: &AuthenticationService{}, Profile: &UserProfileServer{}, CredentialManagement: NewCredentialManagementService(h, gate), MaxAuthenticationMessageBytes: 65536}}, nil)
	for _, tc := range []struct {
		path, body string
		code       int
	}{
		{"/v1/users/me/credentials:list", strings.Repeat(" ", 16385) + "{}", 413},
		{"/v1/users/me/credentials:list?cursor=id", "{}", 400},
		{"/v1/users/me/credentials:list", "{}", 200},
	} {
		req := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-iwut-session", managementToken())
		req.Header.Set("X-Forwarded-For", "192.0.2.99")
		req.RemoteAddr = "192.0.2.1:12000"
		out := httptest.NewRecorder()
		server.ServeHTTP(out, req)
		if out.Code != tc.code || out.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(out.Code, out.Body.String(), out.Header())
		}
	}
	if h.calls != 1 || gate.source != "192.0.2.1" {
		t.Fatal(h.calls, gate.source)
	}
	gate.denied = true
	req := httptest.NewRequest("POST", "/v1/users/me/credentials:list", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-iwut-session", managementToken())
	out := httptest.NewRecorder()
	server.ServeHTTP(out, req)
	if out.Code != 429 || out.Header().Get("Retry-After") != "60" || h.calls != 1 {
		t.Fatal(out.Code, out.Header(), h.calls)
	}
}
