package transport

import (
	api "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"net"
	"testing"
)

func TestRetiredRegistrationGeneratedClientReturnsUnimplemented(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	api.RegisterAuthenticationServiceServer(server, NewRegistrationHandler())
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client := api.NewAuthenticationServiceClient(conn)
	if _, err = client.BeginUserRegistration(t.Context(), &api.BeginUserRegistrationRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
	if _, err = client.CompleteUserRegistration(t.Context(), &api.CompleteUserRegistrationRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
}
