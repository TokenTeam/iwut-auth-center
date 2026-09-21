package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
	"iwut-auth-center/internal/adapter/catalog"
	"iwut-auth-center/internal/config"
)

func TestE2E_UCAUTH001_ReturnsHardcodedCatalogOverRealGRPC(t *testing.T) {
	address := reserveAddress(t)
	configuration, err := config.Load(func(key string) (string, bool) {
		if key == config.GRPCAddrEnv {
			return address, true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	app, err := wireApp(configuration)
	if err != nil {
		t.Fatalf("wireApp() error = %v", err)
	}

	runDone := make(chan struct{})
	var runErr error
	go func() {
		runErr = app.Run()
		close(runDone)
	}()
	t.Cleanup(func() {
		if err := app.Stop(); err != nil {
			t.Errorf("app.Stop() error = %v", err)
		}
		select {
		case <-runDone:
		case <-time.After(10 * time.Second):
			t.Error("app.Run() did not stop")
		}
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.Errorf("app.Run() error = %v", runErr)
		}
	})

	connection := dialGRPC(t, address, runDone, &runErr)
	t.Cleanup(func() { _ = connection.Close() })
	client := scopecatalogv1.NewScopeCatalogClient(connection)
	response, err := client.GetScopeCatalogSnapshot(t.Context(), &scopecatalogv1.GetScopeCatalogSnapshotRequest{})
	if err != nil {
		t.Fatalf("GetScopeCatalogSnapshot() error = %v", err)
	}
	if response.GetRevision() != catalog.HardcodedRevision || !response.GetGeneratedAt().AsTime().Equal(catalog.HardcodedGeneratedAt) {
		t.Fatalf("snapshot metadata = (%d, %v)", response.GetRevision(), response.GetGeneratedAt())
	}
	want := []struct {
		name        string
		requestable bool
	}{
		{name: "legacy.profile", requestable: false},
		{name: "profile.basic", requestable: true},
		{name: "schedule.read", requestable: true},
	}
	if len(response.GetScopes()) != len(want) {
		t.Fatalf("scope count = %d, want %d", len(response.GetScopes()), len(want))
	}
	for index, expected := range want {
		got := response.GetScopes()[index]
		if got.GetName() != expected.name || got.GetRequestable() != expected.requestable {
			t.Fatalf("scope[%d] = (%q, %t), want (%q, %t)", index, got.GetName(), got.GetRequestable(), expected.name, expected.requestable)
		}
	}
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release address: %v", err)
	}
	return address
}

func dialGRPC(t *testing.T, address string, runDone <-chan struct{}, runErr *error) *grpc.ClientConn {
	t.Helper()
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	connection.Connect()
	deadline := time.Now().Add(15 * time.Second)
	for {
		state := connection.GetState()
		if state == connectivity.Ready {
			return connection
		}
		select {
		case <-runDone:
			_ = connection.Close()
			t.Fatalf("app.Run() exited before gRPC was ready: %v", *runErr)
		default:
		}
		if time.Now().After(deadline) {
			_ = connection.Close()
			t.Fatalf("gRPC did not become ready; state = %v", state)
		}
		waitCtx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		connection.WaitForStateChange(waitCtx, state)
		cancel()
	}
}
