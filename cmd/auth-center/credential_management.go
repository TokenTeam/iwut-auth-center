package main

import (
	"context"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/closureworker"
	"iwut-auth-center/internal/adapter/credentialprotocol"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/sessionmanagementrate"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
	uc "iwut-auth-center/internal/credentialmanagement/usecase"
	"log/slog"
	"time"
)

type credentialManagementRuntime struct {
	Service *transport.CredentialManagementService
	Worker  *closureworker.Worker
}

func provideCredentialManagement(c config.Config, db *m.Database, password *passwordRuntime) (*credentialManagementRuntime, error) {
	runtime := &credentialManagementRuntime{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	active := c.CredentialManagement != nil
	if !active {
		n, err := db.Collection(ma.CredentialManagementOperationCollection).CountDocuments(ctx, map[string]any{}, options.Count().SetLimit(1))
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return runtime, nil
		}
	}
	if err := ma.EnsureAuthenticationSchema(ctx, db); err != nil {
		return nil, err
	}
	if err := ma.EnsureCredentialManagementSchema(ctx, db); err != nil {
		return nil, err
	}
	serviceID := "credential-maintenance"
	if c.UserEndpoints != nil {
		serviceID = c.UserEndpoints.Authentication.ServiceID
	}
	auth, err := ma.NewAuthenticationRepository(db, 10000, 5)
	if err != nil {
		return nil, err
	}
	repo, err := ma.NewCredentialManagementRepository(auth, serviceID)
	if err != nil {
		return nil, err
	}
	runtime.Worker, err = closureworker.New(repo, time.Second, func(error) {
		slog.Error("credential operation cleanup requires attention", "error.type", "credential_management_cleanup")
	})
	if err != nil {
		return nil, err
	}
	if !active {
		return runtime, nil
	}
	if password == nil || password.Reauth == nil || c.UserEndpoints == nil {
		return nil, config.ErrInvalidConfiguration
	}
	protocol, err := credentialprotocol.New(serviceID)
	if err != nil {
		return nil, err
	}
	cc := c.CredentialManagement
	gate, err := sessionmanagementrate.New(cc.GlobalPerMinute, cc.SourcePerMinute, cc.AccountPerMinute, cc.MaxBuckets)
	if err != nil {
		return nil, err
	}
	service, err := uc.New(repo, protocol, password.Reauth, gate, serviceID)
	if err != nil {
		return nil, err
	}
	runtime.Service = transport.NewCredentialManagementService(service, gate)
	return runtime, nil
}
