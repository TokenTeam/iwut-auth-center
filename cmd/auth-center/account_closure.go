package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	closure "iwut-auth-center/internal/accountclosure/usecase"
	"iwut-auth-center/internal/adapter/closureprotocol"
	"iwut-auth-center/internal/adapter/closureworker"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/terminationledger"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
	passwordport "iwut-auth-center/internal/password/port"
)

type accountClosureRuntime struct {
	Service *transport.AccountClosureService
	Worker  *closureworker.Worker
}

func provideAccountClosure(configuration config.Config, db *m.Database, endpoints *transport.UserEndpoints, owner *ownerExitRuntime, passwords *passwordRuntime) (*accountClosureRuntime, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	c := configuration.AccountClosure
	if c == nil {
		// Once termination exists, disabling a public route cannot bypass replay or cleanup.
		for name, filter := range map[string]bson.M{
			ma.PrincipalCollection:          {"accountStatus": "CLOSED"},
			ma.AccountClosureTaskCollection: {},
			ma.AccountClosureCollection:     {},
			ma.OwnerExitCollection:          {"purpose": "ACCOUNT_CLOSURE", "appAcknowledged": bson.M{"$ne": true}},
		} {
			n, err := db.Collection(name).CountDocuments(ctx, filter, options.Count().SetLimit(1))
			if err != nil || n != 0 {
				return nil, errors.New("account closure ledger runtime is required by persisted termination state")
			}
		}
		return &accountClosureRuntime{}, nil
	}
	if endpoints == nil || configuration.UserEndpoints == nil || owner == nil || owner.App == nil || owner.Repository == nil {
		return nil, errors.New("account closure requires owner exit and authentication runtimes")
	}
	var verifier passwordport.PasswordVerifier
	if passwords != nil && passwords.Reauth != nil {
		verifier = passwords.Reauth
	}
	if c.Enabled && verifier == nil {
		return nil, errors.New("public account closure requires password verification runtime")
	}
	ledger, err := terminationledger.Open(c.LedgerDir)
	if err != nil {
		return nil, err
	}
	auth, err := ma.NewAuthenticationRepository(db, configuration.UserEndpoints.Authentication.MaxPending, configuration.UserEndpoints.Authentication.MaxFailures)
	if err != nil {
		return nil, err
	}
	if err = ma.EnsureAccountClosureSchema(ctx, db); err != nil {
		return nil, err
	}
	repo, err := ma.NewAccountClosureRepository(auth)
	if err != nil {
		return nil, err
	}
	protocol, err := closureprotocol.New(configuration.UserEndpoints.Authentication.ServiceID)
	if err != nil {
		return nil, err
	}
	service, err := closure.New(repo, protocol, owner.App, owner.Repository, ledger, configuration.UserEndpoints.Authentication.ServiceID, verifier)
	if err != nil {
		return nil, err
	}
	if err = service.ConfigureLimits(c.ReadPerMinute, c.WritePerMinute, c.MaxBuckets); err != nil {
		return nil, err
	}
	// Replay is independent of App availability and completes before either listener opens.
	if err = service.Reconcile(ctx); err != nil {
		return nil, errors.New("account closure startup reconciliation failed")
	}
	limiter, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 1000000, CompleteGlobal: 1000000, BeginSource: c.ReadPerMinute, CompleteLocator: c.WritePerMinute, MaxBuckets: c.MaxBuckets})
	if err != nil {
		return nil, err
	}
	worker, err := closureworker.New(service, c.WorkerInterval, func(err error) {
		slog.Error("account closure cleanup requires attention", "error.type", "account_closure_cleanup")
	})
	if err != nil {
		return nil, err
	}
	return &accountClosureRuntime{Service: transport.NewAccountClosureService(service, c.Enabled, limiter), Worker: worker}, nil
}
