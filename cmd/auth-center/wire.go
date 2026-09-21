//go:build wireinject
// +build wireinject

package main

import (
	"github.com/go-kratos/kratos/v2"
	"github.com/goforj/wire"

	"iwut-auth-center/internal/adapter/catalog"
	"iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
	developerusecase "iwut-auth-center/internal/developer/usecase"
	"iwut-auth-center/internal/scope/usecase"
)

func wireApp(configuration config.Config) (*kratos.App, func(), error) {
	panic(wire.Build(
		catalog.ProviderSet,
		mongo.ProviderSet,
		transport.ProviderSet,
		usecase.NewGetScopeCatalogSnapshotHandler,
		developerusecase.NewBatchGetDeveloperStatusesHandler,
		wire.Bind(new(transport.GetScopeCatalogSnapshotHandler), new(*usecase.GetScopeCatalogSnapshotHandler)),
		wire.Bind(new(transport.BatchGetDeveloperStatusesHandler), new(*developerusecase.BatchGetDeveloperStatusesHandler)),
		provideMongoClient,
		provideMongoDatabase,
		provideServerConfig,
		provideApp,
	))
}
