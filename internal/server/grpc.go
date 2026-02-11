package server

import (
	authpb "iwut-auth-center/api/auth_center/v1/auth"
	oauth2pb "iwut-auth-center/api/auth_center/v1/oauth2"
	userpb "iwut-auth-center/api/auth_center/v1/user"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/middleware"
	"iwut-auth-center/internal/service"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	"github.com/go-kratos/kratos/v2/transport/grpc"
)

// NewGRPCServer new a gRPC server.
func NewGRPCServer(c *conf.Server, authSvc *service.AuthService, userSvc *service.UserService, oauth2Service *service.Oauth2Service, jwtCheck *middleware.JwtCheckMiddleware, logger log.Logger) *grpc.Server {
	var opts = []grpc.ServerOption{
		grpc.Middleware(
			recovery.Recovery(),
			tracing.Server(),
			logging.Server(logger),
			middleware.GetAuditInfoCollectorMiddleware(),
			jwtCheck.GetJwtInfoMiddleware(),
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
	oauth2pb.RegisterOAuth2Server(srv, oauth2Service)
	return srv
}
