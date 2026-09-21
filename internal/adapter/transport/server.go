package transport

import (
	"errors"

	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"

	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
)

type ServerConfig struct {
	GRPCAddr string
}

func NewGRPCServer(configuration ServerConfig, service *ScopeCatalogService) (*kgrpc.Server, error) {
	if configuration.GRPCAddr == "" {
		return nil, errors.New("gRPC address is required")
	}
	if service == nil {
		return nil, errors.New("scope catalog service is required")
	}
	server := kgrpc.NewServer(kgrpc.Address(configuration.GRPCAddr))
	scopecatalogv1.RegisterScopeCatalogServer(server, service)
	return server, nil
}
