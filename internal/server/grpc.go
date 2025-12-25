package server

import (
	authpb "iwut-auth-center/api/auth_center/v1/auth"
	userpb "iwut-auth-center/api/auth_center/v1/user"
	"iwut-auth-center/internal/conf"
	authsvc "iwut-auth-center/internal/service/auth"
	usersvc "iwut-auth-center/internal/service/user"

	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"
)

// NewGRPCServer new a gRPC server.
func NewGRPCServer(c *conf.Server, authSvc *authsvc.Service, userSvc *usersvc.Service) *grpc.Server {
	var opts = []grpc.ServerOption{
		grpc.Middleware(
			recovery.Recovery(),
		),
	}
	if c.Grpc.Network != "" {
		opts = append(opts, grpc.Network(c.Grpc.Network))
	}
	if c.Grpc.Addr != "" {
		opts = append(opts, grpc.Address(c.Grpc.Addr))
	}
	if c.Grpc.Timeout != nil {
		opts = append(opts, grpc.Timeout(c.Grpc.Timeout.AsDuration()))
	}
	srv := grpc.NewServer(opts...)
	authpb.RegisterAuthServer(srv, authSvc)
	userpb.RegisterUserServer(srv, userSvc)
	return srv
}
