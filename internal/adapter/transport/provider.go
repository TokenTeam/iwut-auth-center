package transport

import "github.com/goforj/wire"

var ProviderSet = wire.NewSet(
	NewScopeCatalogService,
	NewDeveloperStatusService,
	NewSystemPrincipalService,
	NewServiceIdentityVerifier,
	NewGRPCServer,
)
