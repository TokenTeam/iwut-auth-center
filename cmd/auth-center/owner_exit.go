package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/oauthcrypto"
	"iwut-auth-center/internal/adapter/ownerexitclient"
	"iwut-auth-center/internal/adapter/ownerexitworker"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
	withdrawal "iwut-auth-center/internal/developerwithdrawal/usecase"
	op "iwut-auth-center/internal/ownerexit/port"
	owner "iwut-auth-center/internal/ownerexit/usecase"
	"net"
	"os"
	"time"
)

type ownerExitRuntime struct {
	Coordinator *owner.Coordinator
	Worker      *ownerexitworker.Worker
	Decision    *transport.OwnerExitDecisionService
	Withdrawal  *transport.DeveloperWithdrawalService
	Repository  *ma.OwnerExitRepository
	App         op.App
}

func provideOwnerExit(configuration config.Config, db *m.Database, endpoints *transport.UserEndpoints) (*ownerExitRuntime, func(), error) {
	cleanup := func() {}
	c := configuration.OwnerExit
	if c == nil {
		return &ownerExitRuntime{}, cleanup, nil
	}
	fail := func() (*ownerExitRuntime, func(), error) {
		cleanup()
		return nil, nil, fmt.Errorf("invalid owner exit deployment configuration")
	}
	if endpoints == nil || configuration.UserEndpoints == nil {
		return fail()
	}
	keyBytes, e := os.ReadFile(c.ServiceKeyFile)
	if e != nil {
		return fail()
	}
	key, e := oauthcrypto.ParseKey(keyBytes)
	if e != nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return fail()
	}
	if id := configuration.IdentityIssuance; id != nil && (key.N.Cmp(id.PrivateKey.N) == 0 || c.ServiceKeyID == id.Kid) {
		return fail()
	}
	if oauth := configuration.OAuth; oauth != nil {
		for _, path := range []string{oauth.OIDCKeyFile, oauth.DelegationKeyFile} {
			raw, e := os.ReadFile(path)
			if e != nil {
				return fail()
			}
			other, e := oauthcrypto.ParseKey(raw)
			if e != nil || other.N.Cmp(key.N) == 0 {
				return fail()
			}
		}
	}
	var creds credentials.TransportCredentials
	if c.AppPlaintextLoopback {
		host, _, e := net.SplitHostPort(c.AppTarget)
		ip := net.ParseIP(host)
		if e != nil || ip == nil || !ip.IsLoopback() {
			return fail()
		}
		creds = insecure.NewCredentials()
	} else {
		roots, e := x509.SystemCertPool()
		if e != nil {
			return fail()
		}
		if c.AppCAFile != "" {
			raw, e := os.ReadFile(c.AppCAFile)
			if e != nil || !roots.AppendCertsFromPEM(raw) {
				return fail()
			}
		}
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: c.AppServerName})
	}
	conn, e := grpc.NewClient(c.AppTarget, grpc.WithTransportCredentials(creds))
	if e != nil {
		return fail()
	}
	cleanup = func() { _ = conn.Close() }
	auth, e := ma.NewAuthenticationRepository(db, configuration.UserEndpoints.Authentication.MaxPending, configuration.UserEndpoints.Authentication.MaxFailures)
	if e != nil {
		return fail()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if ma.EnsureDeveloperWithdrawalSchema(ctx, db) != nil {
		return fail()
	}
	repository := ma.NewOwnerExitRepository(auth)
	app := ownerexitclient.New(conn, oauthcrypto.Key{ID: c.ServiceKeyID, Private: key})
	coordinator := owner.New(repository, app)
	rt := &ownerExitRuntime{Coordinator: coordinator, Worker: ownerexitworker.New(coordinator), Decision: transport.NewOwnerExitDecisionService(repository, c.AppServiceID), Repository: repository, App: app}
	if c.WithdrawalEnabled {
		protocol, e := deviceprotocol.New(configuration.UserEndpoints.Authentication.ServiceID)
		if e != nil {
			return fail()
		}
		limiter, e := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 1000000, CompleteGlobal: 1000000, BeginSource: c.ReadPerMinute, CompleteLocator: c.WritePerMinute, MaxBuckets: c.MaxBuckets})
		if e != nil {
			return fail()
		}
		rt.Withdrawal = transport.NewDeveloperWithdrawalService(withdrawal.New(ma.NewDeveloperWithdrawalRepository(auth), protocol, limiter, coordinator))
	}
	return rt, cleanup, nil
}
