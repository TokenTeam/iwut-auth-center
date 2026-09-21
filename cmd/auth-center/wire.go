//go:build wireinject
// +build wireinject

package main

import (
	"github.com/go-kratos/kratos/v2"
	"github.com/goforj/wire"

	"iwut-auth-center/internal/adapter/catalog"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/scope/usecase"
)

func wireApp(configuration config.Config) (*kratos.App, error) {
	panic(wire.Build(
		catalog.ProviderSet,
		transport.ProviderSet,
		usecase.NewGetScopeCatalogSnapshotHandler,
		wire.Bind(new(transport.GetScopeCatalogSnapshotHandler), new(*usecase.GetScopeCatalogSnapshotHandler)),
		provideServerConfig,
		provideApp,
	))
}
