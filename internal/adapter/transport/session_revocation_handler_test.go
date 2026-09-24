package transport

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	authenticationv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/authentication/usecase"
)

type sessionRevocationTestRepository struct {
	calls int
	err   error
}

func (r *sessionRevocationTestRepository) RevokeCurrentSession(context.Context, []byte, time.Time) error {
	r.calls++
	return r.err
}

type sessionRevocationTestService struct {
	authenticationv1.UnimplementedAuthenticationServiceServer
	handler *SessionRevocationHandler
}

func (s *sessionRevocationTestService) RevokeCurrentSession(ctx context.Context, request *authenticationv1.RevokeCurrentSessionRequest) (*authenticationv1.SessionRevoked, error) {
	return s.handler.RevokeCurrentSession(ctx, request)
}

func TestSessionRevocationGeneratedClientCarrierAndErrors(t *testing.T) {
	repo := &sessionRevocationTestRepository{}
	protocol, _ := deviceprotocol.New("test")
	uc, _ := usecase.NewRevokeCurrentSession(repo, protocol)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	authenticationv1.RegisterAuthenticationServiceServer(server, &sessionRevocationTestService{handler: NewSessionRevocationHandler(uc)})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := authenticationv1.NewAuthenticationServiceClient(conn)
	token, _, _ := protocol.NewSessionToken()
	for _, md := range []metadata.MD{
		{}, metadata.Pairs("authorization", token), metadata.Pairs("x-iwut-session", ""),
		metadata.Pairs("x-iwut-session", token, "x-iwut-session", token),
		metadata.Pairs("x-iwut-session", token+","+token), metadata.Pairs("x-iwut-session", "Bearer "+token),
		metadata.Pairs("x-iwut-session", strings.Repeat("A", 42)+"B"),
		metadata.Pairs("x-iwut-session", strings.Repeat("A", 42)+"="),
		metadata.Pairs("x-iwut-session", strings.Repeat("A", 42)+"+"),
		metadata.Pairs("x-iwut-session", strings.Repeat("A", 42)),
		metadata.Pairs("x-iwut-session", strings.Repeat("A", 8192)),
	} {
		_, err := client.RevokeCurrentSession(metadata.NewOutgoingContext(t.Context(), md), &authenticationv1.RevokeCurrentSessionRequest{})
		assertRevocationError(t, err, codes.InvalidArgument, ReasonInvalidSessionToken)
	}
	if repo.calls != 0 {
		t.Fatalf("invalid requests accessed storage %d times", repo.calls)
	}
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-iwut-session", token, "x-iwut-identity", "invalid-user-jws"))
	for range 2 {
		response, err := client.RevokeCurrentSession(ctx, &authenticationv1.RevokeCurrentSessionRequest{})
		if err != nil || response == nil {
			t.Fatalf("revoke failed: %v", err)
		}
	}
	repo.err = port.ErrUnavailable
	_, err = client.RevokeCurrentSession(ctx, &authenticationv1.RevokeCurrentSessionRequest{})
	assertRevocationError(t, err, codes.Unavailable, ReasonSessionRevocationUnavailable)
}

func assertRevocationError(t *testing.T, err error, code codes.Code, reason string) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("code=%v want %v", status.Code(err), code)
	}
	for _, detail := range status.Convert(err).Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.Reason == reason {
			return
		}
	}
	t.Fatalf("missing reason %s in %v", reason, err)
}
