package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	m "go.mongodb.org/mongo-driver/v2/mongo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"iwut-auth-center/internal/adapter/catalog"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/oauthclient"
	"iwut-auth-center/internal/adapter/oauthclock"
	"iwut-auth-center/internal/adapter/oauthcrypto"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/usecase"
	profiledomain "iwut-auth-center/internal/profile/domain"
	sp "iwut-auth-center/internal/scope/port"
	scopemanagementusecase "iwut-auth-center/internal/scopemanagement/usecase"
)

type oauthRuntime struct {
	Grant           *transport.OAuthGrantService
	Delegation      *transport.OAuthDelegationService
	HTTP            *transport.OAuthHTTP
	Catalog         sp.Catalog
	ScopeManagement *transport.ScopeManagementService
}

func provideOAuth(configuration config.Config, db *m.Database, endpoints *transport.UserEndpoints) (*oauthRuntime, func(), error) {
	return newOAuthRuntime(configuration, db, endpoints, nil)
}

func provideOAuthWithObservability(configuration config.Config, db *m.Database, endpoints *transport.UserEndpoints, observability *observabilityRuntime) (*oauthRuntime, func(), error) {
	return newOAuthRuntime(configuration, db, endpoints, observability.clientInterceptor)
}

func newOAuthRuntime(configuration config.Config, db *m.Database, endpoints *transport.UserEndpoints, tracing grpc.UnaryClientInterceptor) (*oauthRuntime, func(), error) {
	cleanup := func() {}
	c := configuration.OAuth
	if c == nil {
		if configuration.ScopeManagementEnabled {
			return nil, cleanup, fmt.Errorf("scope management requires persistent OAuth configuration")
		}
		cat, err := catalog.NewHardcodedCatalog()
		return &oauthRuntime{Catalog: cat}, cleanup, err
	}
	fail := func() (*oauthRuntime, func(), error) {
		cleanup()
		return nil, nil, fmt.Errorf("invalid OAuth deployment configuration")
	}
	if endpoints == nil {
		return fail()
	}
	readKey := func(path string) (*rsa.PrivateKey, error) {
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		return oauthcrypto.ParseKey(b)
	}
	oidc, e := readKey(c.OIDCKeyFile)
	if e != nil {
		return fail()
	}
	delegation, e := readKey(c.DelegationKeyFile)
	if e != nil {
		return fail()
	}
	service, e := readKey(c.ServiceKeyFile)
	if e != nil || service.N.BitLen() < 2048 || service.Validate() != nil || service.N.Cmp(oidc.N) == 0 || service.N.Cmp(delegation.N) == 0 {
		return fail()
	}
	if user := configuration.IdentityIssuance; user != nil {
		for _, key := range []*rsa.PrivateKey{oidc, delegation, service} {
			if key.N.Cmp(user.PrivateKey.N) == 0 {
				return fail()
			}
		}
		if user.Kid == c.OIDCKeyID || user.Kid == c.DelegationKeyID || user.Kid == c.ServiceKeyID {
			return fail()
		}
	}
	old := map[string]*rsa.PublicKey{}
	for id, path := range c.OldOIDCPublicKeys {
		b, e := os.ReadFile(path)
		if e != nil {
			return fail()
		}
		block, rest := pem.Decode(b)
		if block == nil || strings.TrimSpace(string(rest)) != "" {
			return fail()
		}
		v, e := x509.ParsePKIXPublicKey(block.Bytes)
		if e != nil {
			return fail()
		}
		k, ok := v.(*rsa.PublicKey)
		if !ok {
			return fail()
		}
		if k.N.Cmp(service.N) == 0 {
			return fail()
		}
		if user := configuration.IdentityIssuance; user != nil && k.N.Cmp(user.PrivateKey.N) == 0 {
			return fail()
		}
		old[id] = k
	}
	crypto, e := oauthcrypto.New(oauthcrypto.Key{ID: c.OIDCKeyID, Private: oidc}, oauthcrypto.Key{ID: c.DelegationKeyID, Private: delegation}, old)
	if e != nil {
		return fail()
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
			b, e := os.ReadFile(c.AppCAFile)
			if e != nil || !roots.AppendCertsFromPEM(b) {
				return fail()
			}
		}
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: c.AppServerName})
	}
	clientOptions := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if tracing != nil {
		clientOptions = append(clientOptions, grpc.WithChainUnaryInterceptor(tracing))
	}
	conn, e := grpc.NewClient(c.AppTarget, clientOptions...)
	if e != nil {
		return fail()
	}
	cleanup = func() { _ = conn.Close() }
	repository, e := ma.NewAuthenticationRepository(db, configuration.UserEndpoints.Authentication.MaxPending, configuration.UserEndpoints.Authentication.MaxFailures)
	if e != nil {
		return fail()
	}
	repo := ma.NewOAuthRepository(repository, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if ma.EnsureOAuthSchema(ctx, db) != nil || ma.EnsureApplicationUserStorageSchema(ctx, db) != nil || repo.CheckSectorSuffix(ctx, c.SectorSuffix) != nil {
		return fail()
	}
	file, e := os.Open(c.CatalogFile)
	if e != nil {
		return fail()
	}
	dec := json.NewDecoder(io.LimitReader(file, 128*1024))
	dec.DisallowUnknownFields()
	var seed []d.Scope
	e = dec.Decode(&seed)
	tail := dec.Decode(&struct{}{})
	_ = file.Close()
	if e != nil || tail != io.EOF {
		return fail()
	}
	profileCatalog, e := catalog.NewProfileCatalog(configuration.UserEndpoints.Profile)
	if e != nil {
		return fail()
	}
	profileDefinitions, e := profileCatalog.Snapshot(ctx)
	if e != nil {
		return fail()
	}
	if bindUserInfoProfileScopes(seed, profileDefinitions) != nil {
		return fail()
	}
	app := oauthclient.New(conn, oauthcrypto.Key{ID: c.ServiceKeyID, Private: service})
	uc, e := usecase.New(repo, app, crypto, usecase.Config{Issuer: c.Issuer, SectorSuffix: c.SectorSuffix, RefreshEnabled: c.RefreshEnabled, SigningHealthy: func() bool { return oauthclock.Healthy(c.ClockObservationFile) }})
	if e != nil {
		return fail()
	}
	http := &transport.OAuthHTTP{IPPerMinute: c.IPPerMinute, ClientPerMinute: c.ClientPerMinute, UserConfirmPerMinute: c.UserConfirmPerMinute, Service: uc, Issuer: c.Issuer, Origin: c.PortalOrigin, LoginURL: c.PortalLoginURL, SectorSuffix: c.SectorSuffix, Enabled: c.PublicEnabled, StorageEnabled: configuration.ApplicationUserStorage != nil}
	for _, context := range c.PublicClientContexts {
		http.PublicContexts = append(http.PublicContexts, transport.OAuthPublicContext{ClientID: context.ClientID, Major: context.Major})
	}
	delegationService, e := loadOAuthRoutes(c.RoutePolicyFile, uc)
	if e != nil {
		return fail()
	}
	validate := func(scopes []d.Scope) error {
		return validateOAuthCatalogDeployment(scopes, c.ResourceScopesReady, c.ClockObservationFile != "", configuration.ApplicationUserStorage != nil, delegationService.Routes)
	}
	// Validate every provider and route before first provisioning. Later restarts
	// must never copy manifest enablement or display text over the live catalog.
	if ma.EnsureScopeManagementSchema(ctx, db) != nil || repo.SeedCatalogValidated(ctx, seed, validate) != nil {
		return fail()
	}
	live, e := repo.ReadCatalog(ctx)
	if e != nil || validate(live.Scopes) != nil {
		return fail()
	}
	var management *transport.ScopeManagementService
	if configuration.ScopeManagementEnabled {
		managementRepository, err := ma.NewScopeManagementRepository(repository, seed, validate)
		if err != nil {
			return fail()
		}
		limiter, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 1000000, CompleteGlobal: 1000000, BeginSource: 60, CompleteLocator: 10, MaxBuckets: 4096})
		if err != nil {
			return fail()
		}
		management = transport.NewScopeManagementService(scopemanagementusecase.New(managementRepository, limiter))
	}
	return &oauthRuntime{HTTP: http, Catalog: ma.NewOAuthCatalog(repo), Grant: &transport.OAuthGrantService{Service: uc}, Delegation: delegationService, ScopeManagement: management}, cleanup, nil
}

func validateOAuthCatalogDeployment(scopes []d.Scope, resourcesReady, clockReady, storageEnabled bool, routes map[string]d.Route) error {
	if storageEnabled && validateApplicationUserStorageScopes(scopes) != nil {
		return d.ErrScope
	}
	for _, scope := range scopes {
		if scope.Kind == "RESOURCE" && scope.Enabled && !resourcesReady {
			return d.ErrScope
		}
	}
	if len(routes) > 0 && (!clockReady || !resourcesReady) {
		return d.ErrScope
	}
	for _, route := range routes {
		for _, name := range route.Scopes {
			found := false
			for _, definition := range scopes {
				if definition.Name == name && definition.Kind == "RESOURCE" && definition.Audience == route.Audience && definition.Enabled {
					found = true
				}
			}
			if !found {
				return d.ErrScope
			}
		}
	}
	return nil
}

func validateApplicationUserStorageScopes(scopes []d.Scope) error {
	required := map[string]bool{"storage.read": false, "storage.write": false}
	for _, scope := range scopes {
		if _, relevant := required[scope.Name]; !relevant {
			continue
		}
		if required[scope.Name] || !scope.Enabled || scope.Kind != "RESOURCE" || scope.Audience != "iwut-auth-center" || scope.ProfileField != "" || scope.ProfileValueType != "" {
			return fmt.Errorf("invalid ApplicationUserStorage scope %q", scope.Name)
		}
		required[scope.Name] = true
	}
	for name, found := range required {
		if !found {
			return fmt.Errorf("missing ApplicationUserStorage scope %q", name)
		}
	}
	return nil
}
func provideScopeCatalog(runtime *oauthRuntime) sp.Catalog { return runtime.Catalog }

func bindUserInfoProfileScopes(scopes []d.Scope, definitions []profiledomain.Definition) error {
	profileTypes := map[string]string{}
	for _, definition := range definitions {
		profileTypes[definition.Key] = string(definition.ValueType)
	}
	seen := map[string]bool{}
	for index := range scopes {
		scope := &scopes[index]
		if scope.Kind != "USERINFO_PROFILE" {
			if scope.ProfileField != "" || scope.ProfileValueType != "" {
				return d.ErrScope
			}
			continue
		}
		valueType, ok := profileTypes[scope.ProfileField]
		if !ok || scope.ProfileValueType != "" || scope.Name != "profile."+scope.ProfileField || scope.Audience != "" || seen[scope.ProfileField] {
			return d.ErrScope
		}
		seen[scope.ProfileField] = true
		scope.ProfileValueType = valueType
	}
	return nil
}
