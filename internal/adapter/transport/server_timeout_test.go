package transport

import (
	"context"
	"github.com/go-kratos/kratos/v2/middleware"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type deadlineProbe interface{ Probe(context.Context) }
type deadlineProbeServer struct{ remaining chan time.Duration }

func (s *deadlineProbeServer) Probe(ctx context.Context) {
	at, ok := ctx.Deadline()
	if !ok {
		s.remaining <- 0
		return
	}
	s.remaining <- time.Until(at)
}

func TestBothServerDeadlinesCoverPasswordWorkAndRespectCaller(t *testing.T) {
	probe := &deadlineProbeServer{remaining: make(chan time.Duration, 1)}
	grpcServer := newGRPCServer(ServerConfig{GRPCAddr: "127.0.0.1:0", ObservabilityMiddleware: func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) { probe.Probe(ctx); return next(ctx, req) }
	}}, nil, NewScopeCatalogService(nil), NewDeveloperStatusService(nil), NewSystemPrincipalService(nil))
	grpcServer.RegisterService(&grpc.ServiceDesc{ServiceName: "test.DeadlineProbe", HandlerType: (*deadlineProbe)(nil), Methods: []grpc.MethodDesc{{MethodName: "Probe", Handler: func(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		in := &emptypb.Empty{}
		if err := decode(in); err != nil {
			return nil, err
		}
		call := func(ctx context.Context, _ any) (any, error) {
			return &emptypb.Empty{}, nil
		}
		if interceptor == nil {
			return call(ctx, in)
		}
		return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/test.DeadlineProbe/Probe"}, call)
	}}}}, probe)
	listener := bufconn.Listen(1 << 20)
	go func() { _ = grpcServer.Server.Serve(listener) }()
	t.Cleanup(grpcServer.Server.Stop)
	conn, err := grpc.DialContext(t.Context(), "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	httpServer := newHTTPServer(ServerConfig{HTTPAddr: "127.0.0.1:0"}, nil)
	httpServer.Route("/").GET("/deadline-probe", func(ctx khttp.Context) error { probe.Probe(ctx); return ctx.Result(http.StatusOK, &emptypb.Empty{}) })
	for _, short := range []bool{false, true} {
		ctx := t.Context()
		cancel := func() {}
		if short {
			ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
		}
		for _, kind := range []string{"grpc", "http"} {
			if kind == "grpc" {
				err = conn.Invoke(ctx, "/test.DeadlineProbe/Probe", &emptypb.Empty{}, &emptypb.Empty{})
				if status.Code(err) != codes.PermissionDenied {
					t.Fatal(err)
				}
			} else {
				req := httptest.NewRequest(http.MethodGet, "/deadline-probe", nil).WithContext(ctx)
				rec := httptest.NewRecorder()
				httpServer.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("probe: %d %s", rec.Code, rec.Body)
				}
			}
			remaining := <-probe.remaining
			if short {
				if remaining <= 0 || remaining > 500*time.Millisecond {
					t.Fatalf("%s caller deadline widened: %s", kind, remaining)
				}
			} else if remaining < authRequestTimeout-time.Second || remaining > authRequestTimeout {
				t.Fatalf("%s inherited wrong timeout: %s", kind, remaining)
			}
		}
		cancel()
	}
}
