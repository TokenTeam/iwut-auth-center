package main

import (
	"context"
	"fmt"
	"iwut-auth-center/internal/adapter/identitysigner"
	identityusecase "iwut-auth-center/internal/identity/usecase"
	"time"

	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"iwut-auth-center/internal/adapter/associationcrypto"
	"iwut-auth-center/internal/adapter/catalog"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	mongoadapter "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/transport"
	authusecase "iwut-auth-center/internal/authentication/usecase"
	"iwut-auth-center/internal/config"
	profileusecase "iwut-auth-center/internal/profile/usecase"
	registrationusecase "iwut-auth-center/internal/registration/usecase"
)

// Runtime construction is the startup gate: no RPC listener exists until the
// complete configuration, catalog, indexes and offline migration are verified.
func provideUserEndpoints(configuration config.Config, database *drivermongo.Database) (*transport.UserEndpoints, error) {
	c := configuration.UserEndpoints
	if c == nil {
		return nil, nil
	}
	profileCatalog, err := catalog.NewProfileCatalog(c.Profile)
	if err != nil {
		return nil, err
	}
	profileIdentity, err := transport.NewUserIdentityVerifier(c.UserIdentity)
	if err != nil {
		return nil, err
	}
	protocol, err := deviceprotocol.New(c.Authentication.ServiceID)
	if err != nil {
		return nil, err
	}
	key := func(k config.AssociationKey) associationcrypto.Key {
		return associationcrypto.Key{Version: k.Version, Encrypt: k.Encrypt, Lookup: k.Lookup}
	}
	var previous *associationcrypto.Key
	if c.Association.Previous != nil {
		p := key(*c.Association.Previous)
		previous = &p
	}
	cipher, err := associationcrypto.New(key(c.Association.Current), previous)
	if err != nil {
		return nil, err
	}
	limiter, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: c.Authentication.BeginGlobal, CompleteGlobal: c.Authentication.CompleteGlobal, BeginSource: c.Authentication.BeginSource, CompleteLocator: c.Authentication.CompleteLocator, MaxBuckets: c.Authentication.MaxBuckets})
	if err != nil {
		return nil, err
	}
	repository, err := mongoadapter.NewAuthenticationRepository(database, c.Authentication.MaxPending, c.Authentication.MaxFailures)
	if err != nil {
		return nil, err
	}
	migration, err := mongoadapter.NewAssociationMigrationRepository(database)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := mongoadapter.EnsureAuthenticationSchema(ctx, database); err != nil {
		return nil, fmt.Errorf("ensure authentication schema: %w", err)
	}
	if err := repository.WithAuthTransaction(ctx, func(context.Context) error { return nil }); err != nil {
		return nil, fmt.Errorf("verify Mongo transaction support: %w", err)
	}
	if err := registrationusecase.MigrateAssociations(ctx, migration, cipher, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("association startup gate: %w", err)
	}
	registrationRepo, err := mongoadapter.NewRegistrationRepository(database, repository)
	if err != nil {
		return nil, err
	}
	registration, err := registrationusecase.NewRegistration(registrationRepo, protocol, cipher, limiter, c.Authentication.ServiceID, c.Authentication.SessionTTL)
	if err != nil {
		return nil, err
	}
	login, err := authusecase.NewLogin(repository, protocol, limiter, c.Authentication.ServiceID, c.Authentication.SessionTTL)
	if err != nil {
		return nil, err
	}
	sessions, err := authusecase.NewRevokeCurrentSession(repository, protocol)
	if err != nil {
		return nil, err
	}
	credentials, err := authusecase.NewCredentialRevocation(repository)
	if err != nil {
		return nil, err
	}
	authentication, err := transport.NewAuthenticationService(transport.NewRegistrationHandler(registration, c.Authentication.MaxMessageBytes), transport.NewLoginHandler(login), transport.NewSessionRevocationHandler(sessions), transport.NewCredentialRevocationHandler(credentials))
	if err != nil {
		return nil, err
	}
	profileRepo, err := mongoadapter.NewProfileRepository(database)
	if err != nil {
		return nil, err
	}
	var issuance *transport.UserIdentityService
	if c := configuration.IdentityIssuance; c != nil {
		signer, err := identitysigner.New(c.Issuer, c.Kid, c.PrivateKey)
		if err != nil {
			return nil, err
		}
		repo, err := mongoadapter.NewIdentityRepository(repository)
		if err != nil {
			return nil, err
		}
		service, err := identityusecase.New(repo, signer, protocol, c.TTL)
		if err != nil {
			return nil, err
		}
		issuance = transport.NewUserIdentityService(service)
	}
	return &transport.UserEndpoints{
		IdentityIssuance:              issuance,
		Authentication:                authentication,
		Profile:                       transport.NewUserProfileServer(profileusecase.NewProfileService(profileRepo, profileCatalog)),
		ProfileIdentity:               transport.UserProfileIdentityMiddleware(profileIdentity),
		SessionIdentity:               transport.UserSessionMiddleware(login),
		MaxAuthenticationMessageBytes: c.Authentication.MaxMessageBytes,
	}, nil
}
