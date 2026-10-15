package main

import (
	"context"
	"fmt"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/passwordcrypto"
	"iwut-auth-center/internal/config"
	pwd "iwut-auth-center/internal/password/usecase"
	"os"
	"time"
)

// One engine/executor per process is shared by signup, mutations and dangerous
// actions. Independent factories must not multiply the Argon concurrency budget.
type passwordRuntime struct {
	Engine     *passwordcrypto.Engine
	Protocol   *passwordcrypto.Protocol
	Repository *ma.PasswordRepository
	Quota      *ma.PasswordQuota
	Reauth     *pwd.ReauthService
}

func providePasswordRuntime(c config.Config, db *m.Database) (*passwordRuntime, error) {
	runtime := &passwordRuntime{}
	pc := c.Password
	if pc == nil {
		return runtime, nil
	}
	if c.UserEndpoints == nil || db == nil {
		return nil, fmt.Errorf("password runtime requires authentication endpoints and database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f, err := os.Open(pc.BlocklistFile)
	if err != nil {
		return nil, fmt.Errorf("open pinned password blocklist: %w", err)
	}
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("password blocklist must be a regular file")
	}
	list, err := passwordcrypto.LoadBlocklist(f, pc.BlocklistVersion, pc.BlocklistSource, pc.BlocklistSHA256)
	f.Close()
	if err != nil {
		return nil, err
	}
	executor, err := passwordcrypto.NewExecutor(4, 32, 2*time.Second)
	if err != nil {
		return nil, err
	}
	runtime.Engine, err = passwordcrypto.New(pc.Parameters, list, executor)
	if err != nil {
		return nil, err
	}
	runtime.Protocol, err = passwordcrypto.NewProtocol(pc.OperationKey, c.UserEndpoints.Authentication.ServiceID)
	if err != nil {
		return nil, err
	}
	for _, err := range []error{ma.EnsureAuthenticationSchema(ctx, db), ma.EnsurePasswordSchema(ctx, db), ma.EnsurePasswordQuotaSchema(ctx, db)} {
		if err != nil {
			return nil, err
		}
	}
	auth, err := ma.NewAuthenticationRepository(db, c.UserEndpoints.Authentication.MaxPending, c.UserEndpoints.Authentication.MaxFailures)
	if err != nil {
		return nil, err
	}
	runtime.Repository, err = ma.NewPasswordRepository(auth, runtime.Protocol.KeyID())
	if err != nil {
		return nil, err
	}
	runtime.Quota, err = ma.NewPasswordQuota(auth)
	if err != nil {
		return nil, err
	}
	runtime.Reauth, err = pwd.NewReauth(runtime.Repository, runtime.Engine, runtime.Quota)
	return runtime, err
}
