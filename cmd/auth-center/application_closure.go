package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	m "go.mongodb.org/mongo-driver/v2/mongo"
	"iwut-auth-center/internal/adapter/closereauthsigner"
	"iwut-auth-center/internal/adapter/closureworker"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/transport"
	reauthuc "iwut-auth-center/internal/applicationclosereauth/usecase"
	closureuc "iwut-auth-center/internal/applicationclosure/usecase"
	"iwut-auth-center/internal/config"
)

type applicationClosureRuntime struct {
	Closure *transport.ApplicationClosureService
	Reauth  *transport.ApplicationCloseReauthService
	Worker  *closureworker.Worker
}

func provideApplicationClosure(configuration config.Config, db *m.Database, passwords *passwordRuntime) (*applicationClosureRuntime, error) {
	runtime := &applicationClosureRuntime{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := ma.EnsureApplicationClosureSchema(ctx, db); err != nil {
		return nil, fmt.Errorf("ensure Application closure schema: %w", err)
	}
	if err := ma.EnsureApplicationUserStorageSchema(ctx, db); err != nil {
		return nil, fmt.Errorf("ensure Application user storage schema: %w", err)
	}
	if err := ma.EnsureApplicationUserStorageCleanupSchema(ctx, db); err != nil {
		return nil, fmt.Errorf("ensure Application user storage cleanup schema: %w", err)
	}
	if err := ma.VerifyApplicationClosureConsistency(ctx, db); err != nil {
		return nil, fmt.Errorf("verify Application closure restore consistency: %w", err)
	}
	if err := ma.EnsureAuthenticationSchema(ctx, db); err != nil {
		return nil, fmt.Errorf("ensure authentication transaction fence: %w", err)
	}
	maxPending, maxFailures := 5, 5
	if configuration.UserEndpoints != nil {
		maxPending = configuration.UserEndpoints.Authentication.MaxPending
		maxFailures = configuration.UserEndpoints.Authentication.MaxFailures
	}
	auth, err := ma.NewAuthenticationRepository(db, maxPending, maxFailures)
	if err != nil {
		return nil, err
	}
	if err = ma.ReconcileApplicationUserStorageCleanupTasks(ctx, auth); err != nil {
		return nil, fmt.Errorf("reconcile Application user storage cleanup: %w", err)
	}
	if err = ma.VerifyApplicationUserStorageCleanupConsistency(ctx, db); err != nil {
		return nil, fmt.Errorf("verify Application user storage cleanup consistency: %w", err)
	}
	cleanupRepository, err := ma.NewApplicationClosureRepository(auth)
	if err != nil {
		return nil, err
	}
	runtime.Worker, err = closureworker.New(cleanupRepository, time.Second, func(error) {
		slog.Error("Application user storage cleanup requires attention", "error.type", "application_user_storage_cleanup")
	})
	if err != nil {
		return nil, err
	}
	if c := configuration.ApplicationClosure; c != nil {
		runtime.Closure = transport.NewApplicationClosureService(closureuc.New(cleanupRepository), c.AppServiceID)
	}
	if c := configuration.ApplicationCloseReauth; c != nil {
		if passwords == nil || passwords.Reauth == nil || configuration.UserEndpoints == nil || configuration.IdentityIssuance == nil {
			return nil, fmt.Errorf("Application close reauthentication requires password runtime")
		}
		if err := ma.EnsureApplicationCloseReauthSchema(ctx, db); err != nil {
			return nil, fmt.Errorf("ensure Application close reauth schema: %w", err)
		}
		protocol, err := deviceprotocol.New(configuration.UserEndpoints.Authentication.ServiceID)
		if err != nil {
			return nil, err
		}
		signer, err := closereauthsigner.New(configuration.IdentityIssuance.Kid, configuration.IdentityIssuance.PrivateKey)
		if err != nil {
			return nil, err
		}
		repository, err := ma.NewApplicationCloseReauthRepository(auth, c.AccountPerMinute)
		if err != nil {
			return nil, err
		}
		service, err := reauthuc.New(repository, protocol, signer, configuration.IdentityIssuance.Issuer, passwords.Reauth)
		if err != nil {
			return nil, err
		}
		limiter, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: c.GlobalPerMinute, CompleteGlobal: c.GlobalPerMinute, BeginSource: c.SourcePerMinute, CompleteLocator: c.AccountPerMinute, MaxBuckets: c.MaxBuckets})
		if err != nil {
			return nil, err
		}
		runtime.Reauth = transport.NewApplicationCloseReauthService(service, limiter, c.Enabled)
	}
	return runtime, nil
}
