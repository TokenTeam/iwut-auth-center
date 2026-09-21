package main

import (
	"github.com/go-kratos/kratos/v2"
	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"

	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
)

func provideServerConfig(configuration config.Config) transport.ServerConfig {
	return transport.ServerConfig{GRPCAddr: configuration.GRPCAddr}
}

func provideApp(server *kgrpc.Server) *kratos.App {
	return kratos.New(
		kratos.Name("iwut-auth-center"),
		kratos.Server(server),
	)
}
