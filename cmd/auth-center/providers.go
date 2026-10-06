package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kratos/kratos/v2"
	kt "github.com/go-kratos/kratos/v2/transport"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"

	mongoadapter "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
)

const (
	mongoShutdownTimeout = 5 * time.Second
	mongoSchemaTimeout   = 10 * time.Second
)

func provideMongoClient(configuration config.Config) (*drivermongo.Client, func(), error) {
	client, err := mongoadapter.NewClient(configuration.MongoURI)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), mongoShutdownTimeout)
		defer cancel()
		_ = client.Disconnect(ctx)
	}
	return client, cleanup, nil
}

func provideMongoDatabase(client *drivermongo.Client, configuration config.Config) (*drivermongo.Database, error) {
	database, err := mongoadapter.NewDatabase(client, configuration.MongoDatabase)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), mongoSchemaTimeout)
	defer cancel()
	if err := mongoadapter.EnsurePrincipalSchema(ctx, database); err != nil {
		return nil, fmt.Errorf("ensure principal schema: %w", err)
	}
	if err := mongoadapter.EnsureSystemPrincipalSchema(ctx, database); err != nil {
		return nil, fmt.Errorf("ensure system principal schema: %w", err)
	}
	if err := mongoadapter.BootstrapSystemPrincipals(ctx, database); err != nil {
		return nil, fmt.Errorf("bootstrap system principals: %w", err)
	}
	return database, nil
}

func provideServerConfig(configuration config.Config, endpoints *transport.UserEndpoints, oauth *oauthRuntime, owner *ownerExitRuntime, closure *accountClosureRuntime, applicationClosure *applicationClosureRuntime) transport.ServerConfig {
	return transport.ServerConfig{ApplicationClosure: applicationClosure.Closure, ApplicationCloseReauth: applicationClosure.Reauth, AccountClosure: closure.Service, OwnerExitDecision: owner.Decision, DeveloperWithdrawal: owner.Withdrawal, HTTPAddr: configuration.HTTPAddr, GRPCAddr: configuration.GRPCAddr, UserEndpoints: endpoints, OAuth: oauth.HTTP, OAuthGrant: oauth.Grant, OAuthDelegation: oauth.Delegation}
}

func provideApp(servers *transport.Servers, owner *ownerExitRuntime, closure *accountClosureRuntime) *kratos.App {
	all := []kt.Server{servers.HTTP, servers.GRPC}
	if closure.Worker != nil {
		all = append(all, closure.Worker)
	}
	if owner.Worker != nil {
		all = append(all, owner.Worker)
	}
	return kratos.New(
		kratos.Name("iwut-auth-center"),
		kratos.Server(all...),
	)
}
