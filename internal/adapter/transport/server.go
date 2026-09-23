package transport

import (
	"errors"

	"github.com/go-kratos/kratos/v2/middleware"
	"google.golang.org/grpc"
	authv1 "iwut-auth-center/api/gen/go/auth_center/v1/authentication"
	identityv1 "iwut-auth-center/api/gen/go/auth_center/v1/identity"
	profilev1 "iwut-auth-center/api/gen/go/auth_center/v1/user_profile"
	profiledomain "iwut-auth-center/internal/profile/domain"

	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"

	developerstatusv1 "iwut-auth-center/api/gen/go/auth_center/v1/developer_status"
	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
	systemprincipalv1 "iwut-auth-center/api/gen/go/auth_center/v1/system_principal"
)

type ServerConfig struct {
	HTTPAddr      string
	GRPCAddr      string
	UserEndpoints *UserEndpoints
}

// UserEndpoints is an optional, fully validated runtime assembled before listening.
type UserEndpoints struct {
	IdentityIssuance              *UserIdentityService
	Authentication                *AuthenticationService
	Profile                       *UserProfileServer
	ProfileIdentity               middleware.Middleware
	SessionIdentity               middleware.Middleware
	MaxAuthenticationMessageBytes int
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
	options := []kgrpc.ServerOption{kgrpc.Address(configuration.GRPCAddr)}
	if endpoints := configuration.UserEndpoints; endpoints != nil {
		if endpoints.Authentication == nil || endpoints.Profile == nil || endpoints.ProfileIdentity == nil || endpoints.SessionIdentity == nil || endpoints.MaxAuthenticationMessageBytes <= 0 {
			return nil, errors.New("complete user endpoint runtime is required")
		}
		options = append(options,
			kgrpc.Middleware(userEndpointAuthenticationMiddleware(verifier, endpoints.ProfileIdentity, endpoints.SessionIdentity, true, endpoints.MaxAuthenticationMessageBytes)),
			kgrpc.Options(grpc.ForceServerCodec(NewProfileStrictCodec()), grpc.MaxRecvMsgSize(max(profiledomain.MaxMessageBytes, endpoints.MaxAuthenticationMessageBytes))),
		)
	} else {
		options = append(options, kgrpc.Middleware(serviceIdentityMiddleware(verifier)))
	}
	server := kgrpc.NewServer(options...)
	if endpoints := configuration.UserEndpoints; endpoints != nil {
		authv1.RegisterAuthenticationServiceServer(server, endpoints.Authentication)
		profilev1.RegisterUserProfileServiceServer(server, endpoints.Profile)
		if endpoints.IdentityIssuance != nil {
			identityv1.RegisterUserIdentityServiceServer(server, endpoints.IdentityIssuance)
		}
	}
	scopecatalogv1.RegisterScopeCatalogServer(server, service)
	developerstatusv1.RegisterDeveloperStatusDirectoryServer(server, developerStatusService)
	systemprincipalv1.RegisterSystemPrincipalDirectoryServer(server, systemPrincipalService)
	return server, nil
}
