//go:build wireinject
// +build wireinject

package main

import (
	"github.com/go-kratos/kratos/v2"
	"github.com/goforj/wire"

	"iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
	developerusecase "iwut-auth-center/internal/developer/usecase"
	"iwut-auth-center/internal/scope/usecase"
	systemprincipalusecase "iwut-auth-center/internal/systemprincipal/usecase"
)

func wireApp(configuration config.Config) (*kratos.App, func(), error) {
	panic(wire.Build(
		provideOAuth,
		provideScopeCatalog,
		mongo.ProviderSet,
		transport.ProviderSet,
		usecase.NewGetScopeCatalogSnapshotHandler,
		developerusecase.NewBatchGetDeveloperStatusesHandler,
		systemprincipalusecase.NewResolveSystemPrincipalHandler,
		wire.Bind(new(transport.GetScopeCatalogSnapshotHandler), new(*usecase.GetScopeCatalogSnapshotHandler)),
		wire.Bind(new(transport.BatchGetDeveloperStatusesHandler), new(*developerusecase.BatchGetDeveloperStatusesHandler)),
		wire.Bind(new(transport.ResolveSystemPrincipalHandler), new(*systemprincipalusecase.ResolveSystemPrincipalHandler)),
		provideMongoClient,
		provideMongoDatabase,
		provideUserEndpoints,
		provideServerConfig,
		provideApp,
	))
}
