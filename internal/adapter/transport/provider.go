package transport

import "github.com/goforj/wire"

var ProviderSet = wire.NewSet(
	NewScopeCatalogService,
	NewGRPCServer,
)
