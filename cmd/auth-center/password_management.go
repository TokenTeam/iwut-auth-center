package main

import (
	"context"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/closureworker"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/passwordcrypto"
	"iwut-auth-center/internal/adapter/smtpmail"
	"iwut-auth-center/internal/adapter/transport"
	"iwut-auth-center/internal/config"
	p "iwut-auth-center/internal/password/port"
	uc "iwut-auth-center/internal/password/usecase"
	"log/slog"
	"strings"
	"time"
)

type passwordManagementRuntime struct {
	Service *transport.PasswordManagementService
	Login   *transport.PasswordLoginService
	Worker  *closureworker.Worker
}

func providePasswordManagement(c config.Config, db *m.Database, password *passwordRuntime) (*passwordManagementRuntime, error) {
	runtime := &passwordManagementRuntime{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	persisted := false
	for _, col := range []string{ma.PasswordChangeCollection, ma.PasswordResetCollection, ma.PasswordLoginCollection, ma.PasswordNotificationCollection} {
		n, err := db.Collection(col).CountDocuments(ctx, map[string]any{}, options.Count().SetLimit(1))
		if err != nil {
			return nil, err
		}
		persisted = persisted || n > 0
	}
	if !c.PasswordManagement && !persisted {
		return runtime, nil
	}
	for _, err := range []error{ma.EnsureAuthenticationSchema(ctx, db), ma.EnsurePasswordSchema(ctx, db), ma.EnsurePasswordResetSchema(ctx, db), ma.EnsurePasswordLoginSchema(ctx, db)} {
		if err != nil {
			return nil, err
		}
	}
	auth, err := ma.NewAuthenticationRepository(db, 10000, 5)
	if err != nil {
		return nil, err
	}
	keyID := strings.Repeat("0", 64)
	serviceID := "password-maintenance"
	if c.UserEndpoints != nil {
		serviceID = c.UserEndpoints.Authentication.ServiceID
	}
	if password.Protocol != nil {
		keyID = password.Protocol.KeyID()
	}
	repo, err := ma.NewPasswordRepository(auth, keyID)
	if err != nil {
		return nil, err
	}
	device, err := deviceprotocol.New(serviceID)
	if err != nil {
		return nil, err
	}
	var sender p.NotificationSender
	timeout := 10 * time.Second
	var mail *smtpmail.Sender
	if ec := c.EmailBinding; ec != nil {
		mail, err = smtpmail.New(smtpmail.Config{Address: ec.SMTPAddress, From: ec.SMTPFrom, TLSMode: ec.SMTPTLSMode, Username: ec.SMTPUsername, Password: ec.SMTPPassword, Roots: ec.SMTPRoots, Timeout: ec.SMTPTimeout})
		if err != nil {
			return nil, err
		}
		sender = mail
		timeout = min(ec.SMTPTimeout, time.Minute)
	}
	runtime.Worker, err = closureworker.New(uc.NewNotifications(repo, sender, device, timeout), time.Second, func(error) {
		slog.Error("password background task requires attention", "error.type", "password_background")
	})
	if err != nil {
		return nil, err
	}
	if !c.PasswordManagement {
		return runtime, nil
	}
	if c.Password == nil || c.UserEndpoints == nil || password.Engine == nil || password.Protocol == nil || password.Quota == nil || mail == nil {
		return nil, config.ErrInvalidConfiguration
	}
	change, err := uc.NewChangeService(repo, password.Engine, password.Protocol, device, password.Quota, c.UserEndpoints.Authentication.SessionTTL)
	if err != nil {
		return nil, err
	}
	ec := c.EmailBinding
	resetRepo, err := ma.NewPasswordResetRepository(repo, password.Protocol, ma.EmailLimits{OwnerHourly: ec.OwnerHourly, EmailHourly: ec.EmailHourly, SourceHourly: ec.SourceHourly, MaxBuckets: ec.MaxBuckets})
	if err != nil {
		return nil, err
	}
	budget, err := passwordcrypto.NewAddressBudget(ec.HMACKey)
	if err != nil {
		return nil, err
	}
	reset, err := uc.NewResetService(resetRepo, password.Protocol, device, password.Engine, password.Quota, mail, serviceID, budget)
	if err != nil {
		return nil, err
	}
	runtime.Service = transport.NewPasswordManagementService(change, reset)
	if c.PasswordLogin {
		loginRepo, err := ma.NewPasswordLoginRepository(repo, password.Protocol)
		if err != nil {
			return nil, err
		}
		dummy, err := password.Engine.DummyMaterial()
		if err != nil {
			return nil, err
		}
		login, err := uc.NewLoginService(loginRepo, password.Engine, password.Protocol, device, password.Quota, budget, dummy, c.UserEndpoints.Authentication.SessionTTL)
		if err != nil {
			return nil, err
		}
		runtime.Login = transport.NewPasswordLoginService(login)
	}
	return runtime, nil
}
