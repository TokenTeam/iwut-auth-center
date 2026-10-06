package main

import (
	"context"
	"fmt"
	"time"

	m "go.mongodb.org/mongo-driver/v2/mongo"
	"iwut-auth-center/internal/adapter/closereauthsigner"
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
}

func provideApplicationClosure(configuration config.Config, db *m.Database) (*applicationClosureRuntime, error) {
	runtime := &applicationClosureRuntime{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := ma.EnsureApplicationClosureSchema(ctx, db); err != nil {
		return nil, fmt.Errorf("ensure Application closure schema: %w", err)
	}
	if err := ma.VerifyApplicationClosureConsistency(ctx, db); err != nil {
		return nil, fmt.Errorf("verify Application closure restore consistency: %w", err)
	}
	if configuration.ApplicationClosure == nil && configuration.ApplicationCloseReauth == nil {
		return runtime, nil
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
	if c := configuration.ApplicationClosure; c != nil {
		repository, err := ma.NewApplicationClosureRepository(auth)
		if err != nil {
			return nil, err
		}
		runtime.Closure = transport.NewApplicationClosureService(closureuc.New(repository), c.AppServiceID)
	}
	if c := configuration.ApplicationCloseReauth; c != nil {
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
		service, err := reauthuc.New(repository, protocol, signer, configuration.IdentityIssuance.Issuer)
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
