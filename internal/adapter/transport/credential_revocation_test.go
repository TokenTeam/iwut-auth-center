package transport

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/authentication/usecase"
)

const revokeTestCredential = "12345678-1234-4234-8234-123456789abc"
const revokeTestToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type revokeTestChecker struct{}

func (revokeTestChecker) Check(_ context.Context, token string) (domain.Session, error) {
	if token != revokeTestToken {
		return domain.Session{}, port.ErrSessionInvalid
	}
	return domain.Session{SessionID: "trusted-session", AuthID: "trusted-owner", CredentialID: revokeTestCredential, TokenDigest: make([]byte, 32)}, nil
}

type revokeTestRepository struct{}

func (revokeTestRepository) RevokeOwnCredential(_ context.Context, caller domain.Session, id string, _ time.Time) error {
	if caller.AuthID != "trusted-owner" || caller.SessionID != "trusted-session" {
		return errors.New("untrusted caller")
	}
	if id != revokeTestCredential {
		return port.ErrNotFound
	}
	return nil
}

type revokeTestServer struct {
	authv1.UnimplementedAuthenticationServiceServer
	handler *CredentialRevocationHandler
}

func (s *revokeTestServer) RevokeOwnCredential(ctx context.Context, r *authv1.RevokeOwnCredentialRequest) (*authv1.CredentialRevoked, error) {
	return s.handler.RevokeOwnCredential(ctx, r)
}

func TestCredentialRevocationTransportSessionBoundary(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	revoke, _ := usecase.NewCredentialRevocation(revokeTestRepository{})
	handler := NewCredentialRevocationHandler(revoke)
	server := kgrpc.NewServer(kgrpc.Listener(listener), kgrpc.Middleware(UserSessionMiddleware(revokeTestChecker{})))
	authv1.RegisterAuthenticationServiceServer(server, &revokeTestServer{handler: handler})
	done := make(chan error, 1)
	go func() { done <- server.Start(context.Background()) }()
	t.Cleanup(func() { _ = server.Stop(context.Background()); <-done })
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := authv1.NewAuthenticationServiceClient(conn)
	cases := []struct {
		name    string
		headers []string
		target  string
		code    codes.Code
	}{
		{"valid", []string{"x-iwut-session", revokeTestToken}, revokeTestCredential, codes.OK},
		{"missing", nil, revokeTestCredential, codes.Unauthenticated},
		{"empty", []string{"x-iwut-session", ""}, revokeTestCredential, codes.Unauthenticated},
		{"duplicate", []string{"x-iwut-session", revokeTestToken, "x-iwut-session", revokeTestToken}, revokeTestCredential, codes.Unauthenticated},
		{"bearer", []string{"x-iwut-session", "Bearer " + revokeTestToken}, revokeTestCredential, codes.Unauthenticated},
		{"whitespace", []string{"x-iwut-session", " " + revokeTestToken}, revokeTestCredential, codes.Unauthenticated},
		{"merged", []string{"x-iwut-session", revokeTestToken + "," + revokeTestToken}, revokeTestCredential, codes.Unauthenticated},
		{"padded", []string{"x-iwut-session", revokeTestToken + "="}, revokeTestCredential, codes.Unauthenticated},
		{"padding-bits", []string{"x-iwut-session", strings.Repeat("A", 42) + "B"}, revokeTestCredential, codes.Unauthenticated},
		{"authorization", []string{"authorization", revokeTestToken}, revokeTestCredential, codes.Unauthenticated},
		{"identity", []string{"x-iwut-identity", revokeTestToken}, revokeTestCredential, codes.Unauthenticated},
		{"invalid-session", []string{"x-iwut-session", strings.Repeat("B", 42) + "A"}, revokeTestCredential, codes.Unauthenticated},
		{"no-target", []string{"x-iwut-session", revokeTestToken}, "", codes.InvalidArgument},
		{"uppercase-id", []string{"x-iwut-session", revokeTestToken}, strings.ToUpper(revokeTestCredential), codes.InvalidArgument},
		{"unknown-target", []string{"x-iwut-session", revokeTestToken}, "87654321-1234-4234-8234-123456789abc", codes.NotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if len(tc.headers) > 0 {
				ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(tc.headers...))
			}
			_, err := client.RevokeOwnCredential(ctx, &authv1.RevokeOwnCredentialRequest{CredentialId: tc.target})
			if status.Code(err) != tc.code {
				t.Fatalf("got %v want %v: %v", status.Code(err), tc.code, err)
			}
		})
	}
	// Calling a handler directly with arbitrary metadata never constructs identity.
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("x-iwut-session", revokeTestToken, "auth-id", "trusted-owner"))
	if _, err := handler.RevokeOwnCredential(ctx, &authv1.RevokeOwnCredentialRequest{CredentialId: revokeTestCredential}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
}

func TestCredentialRevocationUnavailableNeverClaimsRollback(t *testing.T) {
	for _, err := range []error{port.ErrUnavailable, context.DeadlineExceeded, errors.New("unknown commit result")} {
		got := credentialRevocationError(err)
		if status.Code(got) != codes.Unavailable {
			t.Fatal(got)
		}
		if strings.Contains(got.Error(), err.Error()) && err != port.ErrUnavailable {
			t.Fatal("leaked underlying error", got)
		}
	}
}
