package transport

import (
	"errors"

	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"

	developerstatusv1 "iwut-auth-center/api/gen/go/auth_center/v1/developer_status"
	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
	systemprincipalv1 "iwut-auth-center/api/gen/go/auth_center/v1/system_principal"
)

type ServerConfig struct {
	GRPCAddr string
}

func NewGRPCServer(
	configuration ServerConfig,
	verifier *ServiceIdentityVerifier,
	service *ScopeCatalogService,
	developerStatusService *DeveloperStatusService,
	systemPrincipalService *SystemPrincipalService,
) (*kgrpc.Server, error) {
	if configuration.GRPCAddr == "" {
		return nil, errors.New("gRPC address is required")
	}
	if service == nil {
		return nil, errors.New("scope catalog service is required")
	}
	if developerStatusService == nil {
		return nil, errors.New("developer status service is required")
	}
	if verifier == nil {
		return nil, errors.New("service identity verifier is required")
	}
	if systemPrincipalService == nil {
		return nil, errors.New("system principal service is required")
	}
	server := kgrpc.NewServer(
		kgrpc.Address(configuration.GRPCAddr),
		kgrpc.Middleware(serviceIdentityMiddleware(verifier)),
	)
	scopecatalogv1.RegisterScopeCatalogServer(server, service)
	developerstatusv1.RegisterDeveloperStatusDirectoryServer(server, developerStatusService)
	systemprincipalv1.RegisterSystemPrincipalDirectoryServer(server, systemPrincipalService)
	return server, nil
}
