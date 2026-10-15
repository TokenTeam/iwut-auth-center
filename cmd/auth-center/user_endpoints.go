package main

import (
	"context"
	"fmt"
	academicyearusecase "iwut-auth-center/internal/academicyear/usecase"
	accountusecase "iwut-auth-center/internal/account/usecase"
	"iwut-auth-center/internal/adapter/emailaccountprotocol"
	"iwut-auth-center/internal/adapter/emailloginprotocol"
	"iwut-auth-center/internal/adapter/identitysigner"
	"iwut-auth-center/internal/adapter/sessionmanagementrate"
	"iwut-auth-center/internal/adapter/smtpmail"
	adminusecase "iwut-auth-center/internal/administrator/usecase"
	applicationoperationsusecase "iwut-auth-center/internal/applicationoperations/usecase"
	applicationuserstorageusecase "iwut-auth-center/internal/applicationuserstorage/usecase"
	developerusecase "iwut-auth-center/internal/developer/usecase"
	emailaccountusecase "iwut-auth-center/internal/emailaccount/usecase"
	emaildomain "iwut-auth-center/internal/emailbinding/domain"
	emailloginusecase "iwut-auth-center/internal/emaillogin/usecase"
	identityusecase "iwut-auth-center/internal/identity/usecase"
	reviewerusecase "iwut-auth-center/internal/reviewer/usecase"
	sessionmanagementusecase "iwut-auth-center/internal/sessionmanagement/usecase"
	"time"

	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"iwut-auth-center/internal/adapter/catalog"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	mongoadapter "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/transport"
	authusecase "iwut-auth-center/internal/authentication/usecase"
	"iwut-auth-center/internal/config"
	profileusecase "iwut-auth-center/internal/profile/usecase"
)

// Runtime construction is the startup gate: no RPC listener exists until the
// complete configuration, catalog, indexes and transaction support are verified.
func provideUserEndpoints(configuration config.Config, database *drivermongo.Database, passwordsRuntime *passwordRuntime, credentialRuntime *credentialManagementRuntime, passwordManagement *passwordManagementRuntime) (*transport.UserEndpoints, error) {
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
	limiter, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: c.Authentication.BeginGlobal, CompleteGlobal: c.Authentication.CompleteGlobal, BeginSource: c.Authentication.BeginSource, CompleteLocator: c.Authentication.CompleteLocator, MaxBuckets: c.Authentication.MaxBuckets})
	if err != nil {
		return nil, err
	}
	repository, err := mongoadapter.NewAuthenticationRepository(database, c.Authentication.MaxPending, c.Authentication.MaxFailures)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := mongoadapter.EnsureAuthenticationSchema(ctx, database); err != nil {
		return nil, fmt.Errorf("ensure authentication schema: %w", err)
	}
	if err := mongoadapter.EnsureCampusSchema(ctx, database); err != nil {
		return nil, fmt.Errorf("ensure campus schema: %w", err)
	}
	if err := mongoadapter.EnsurePlatformAdministratorSchema(ctx, database); err != nil {
		return nil, err
	}
	if err := mongoadapter.EnsureAcademicYearSchema(ctx, database); err != nil {
		return nil, err
	}
	if err := mongoadapter.EnsureReviewerSchema(ctx, database); err != nil {
		return nil, err
	}
	if err := repository.WithAuthTransaction(ctx, func(context.Context) error { return nil }); err != nil {
		return nil, fmt.Errorf("verify Mongo transaction support: %w", err)
	}
	academicYearRepository, err := mongoadapter.NewAcademicYearRepository(repository)
	if err != nil {
		return nil, err
	}
	if err := academicYearRepository.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("initialize academic year policy: %w", err)
	}
	registrationRepo, err := mongoadapter.NewRegistrationRepository(database, repository)
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
	authentication, err := transport.NewAuthenticationService(nil, transport.NewLoginHandler(login), transport.NewSessionRevocationHandler(sessions), transport.NewCredentialRevocationHandler(credentials))
	if err != nil {
		return nil, err
	}
	profileRepo, err := mongoadapter.NewProfileRepository(database, repository)
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
	reviewerRepo, err := mongoadapter.NewReviewerRepository(repository)
	if err != nil {
		return nil, err
	}

	var emailService *transport.EmailBindingService
	var emailAccount *transport.EmailAccountService
	var emailAccountCore *emailaccountusecase.Service
	if pc := configuration.Password; pc != nil {
		ec := configuration.EmailBinding
		engine := passwordsRuntime.Engine
		passwords := passwordsRuntime.Repository
		quota := passwordsRuntime.Quota
		if engine == nil || passwords == nil || quota == nil {
			return nil, fmt.Errorf("password runtime is required by email v3")
		}

		ep, err := emailaccountprotocol.New(ec.HMACKey, pc.OperationKey, c.Authentication.ServiceID)
		if err != nil {
			return nil, err
		}
		if err = mongoadapter.EnsureEmailAccountSchema(ctx, database); err != nil {
			return nil, err
		}
		repo, err := mongoadapter.NewEmailAccountRepository(registrationRepo, passwords, ep.KeyID(), mongoadapter.EmailLimits{OwnerHourly: ec.OwnerHourly, EmailHourly: ec.EmailHourly, SourceHourly: ec.SourceHourly, MaxBuckets: ec.MaxBuckets})
		if err != nil {
			return nil, err
		}
		sender, err := smtpmail.New(smtpmail.Config{Address: ec.SMTPAddress, From: ec.SMTPFrom, TLSMode: ec.SMTPTLSMode, Username: ec.SMTPUsername, Password: ec.SMTPPassword, Roots: ec.SMTPRoots, Timeout: ec.SMTPTimeout})
		if err != nil {
			return nil, err
		}
		emailAccountCore, err = emailaccountusecase.New(repo, ep, protocol, engine, quota, sender, c.Authentication.ServiceID, c.Authentication.SessionTTL)
		if err != nil {
			return nil, err
		}
		emailAccount = transport.NewEmailAccountService(emailAccountCore)
		emailService = transport.NewEmailBindingProjection(emailAccountCore)
	}

	var emailLoginService *transport.EmailLoginService
	if ec := configuration.EmailLogin; ec != nil {
		ep, err := emailloginprotocol.New(c.Authentication.ServiceID, ec.HMACKey, emaildomain.NormalizeEmail)
		if err != nil {
			return nil, err
		}
		sender, err := smtpmail.New(smtpmail.Config{Address: ec.SMTPAddress, From: ec.SMTPFrom, TLSMode: ec.SMTPTLSMode, Username: ec.SMTPUsername, Password: ec.SMTPPassword, Roots: ec.SMTPRoots, Timeout: ec.SMTPTimeout})
		if err != nil {
			return nil, err
		}
		repo, err := mongoadapter.NewEmailLoginRepository(registrationRepo, ep.KeyID(), mongoadapter.EmailLimits{OwnerHourly: ec.OwnerHourly, EmailHourly: ec.EmailHourly, SourceHourly: ec.SourceHourly, MaxBuckets: ec.MaxBuckets})
		if err != nil {
			return nil, err
		}
		if err = repo.Initialize(ctx, time.Now().UTC()); err != nil {
			return nil, err
		}
		service, err := emailloginusecase.New(repo, ep, protocol, sender, limiter, c.Authentication.ServiceID, c.Authentication.SessionTTL)
		if err != nil {
			return nil, err
		}
		emailLoginService = transport.NewEmailLoginService(service, c.Authentication.MaxMessageBytes)
	}

	var campusCertification *transport.CampusCertificationService
	if configuration.CampusCertification != nil && emailAccountCore != nil {
		campusCertification = transport.NewCampusEmailAlias(emailAccountCore)
	}

	var developerApplication *transport.DeveloperApplicationService
	if dc := configuration.DeveloperApplication; dc != nil {
		if err = mongoadapter.EnsureDeveloperApplicationSchema(ctx, database); err != nil {
			return nil, err
		}
		repo, err := mongoadapter.NewDeveloperApplicationRepository(repository)
		if err != nil {
			return nil, err
		}
		gate, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: dc.GlobalPerMinute, CompleteGlobal: dc.GlobalPerMinute, BeginSource: dc.SourcePerMinute, CompleteLocator: dc.AccountPerMinute, MaxBuckets: dc.MaxBuckets})
		if err != nil {
			return nil, err
		}
		developerApplication = transport.NewDeveloperApplicationService(developerusecase.NewApplication(repo, gate, dc.RecoveryReady && emailLoginService != nil), c.Authentication.MaxMessageBytes)
	}
	var administrator *transport.PlatformAdministratorService
	if ac := configuration.PlatformAdministrator; ac != nil {
		repo, err := mongoadapter.NewPlatformAdministratorRepository(repository, ac.RecoveryReady && emailLoginService != nil)
		if err != nil {
			return nil, err
		}
		gate, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 1000000, CompleteGlobal: 1000000, BeginSource: ac.ReadPerMinute, CompleteLocator: ac.WritePerMinute, MaxBuckets: ac.MaxBuckets})
		if err != nil {
			return nil, err
		}
		administrator = transport.NewPlatformAdministratorService(adminusecase.New(repo, gate))
	}
	var academicYearPolicy *transport.AcademicYearPolicyService
	if ac := configuration.AcademicYearPolicy; ac != nil {
		gate, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 1000000, CompleteGlobal: 1000000, BeginSource: ac.ReadPerMinute, CompleteLocator: ac.WritePerMinute, MaxBuckets: ac.MaxBuckets})
		if err != nil {
			return nil, err
		}
		academicYearPolicy = transport.NewAcademicYearPolicyService(academicyearusecase.New(academicYearRepository, gate))
	}
	var applicationOperations *transport.ApplicationOperationsPermissionService
	if ac := configuration.ApplicationOperationsPermission; ac != nil {
		repo, err := mongoadapter.NewApplicationOperationsPermissionRepository(repository, ac.RecoveryReady && emailLoginService != nil)
		if err != nil {
			return nil, err
		}
		gate, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 1000000, CompleteGlobal: 1000000, BeginSource: ac.ReadPerMinute, CompleteLocator: ac.WritePerMinute, MaxBuckets: ac.MaxBuckets})
		if err != nil {
			return nil, err
		}
		applicationOperations = transport.NewApplicationOperationsPermissionService(applicationoperationsusecase.New(repo, gate))
	}
	var accountManagement *transport.AccountManagementService
	if ac := configuration.AccountManagement; ac != nil {
		if err := mongoadapter.EnsureAccountManagementSchema(ctx, database); err != nil {
			return nil, err
		}
		repo, err := mongoadapter.NewAccountManagementRepository(repository)
		if err != nil {
			return nil, err
		}
		accountManagement = transport.NewAccountManagementService(accountusecase.NewConfigured(repo, ac.ReadPerMinute, ac.WritePerMinute, ac.MaxBuckets))
	}
	var developerManagement *transport.DeveloperManagementService
	if dc := configuration.DeveloperManagement; dc != nil {
		if err := mongoadapter.EnsureDeveloperManagementSchema(ctx, database); err != nil {
			return nil, err
		}
		repo, err := mongoadapter.NewDeveloperManagementRepository(repository, dc.RecoveryReady && emailLoginService != nil)
		if err != nil {
			return nil, err
		}
		gate, err := deviceprotocol.NewLimiter(deviceprotocol.RateLimits{BeginGlobal: 1000000, CompleteGlobal: 1000000, BeginSource: dc.ReadPerMinute, CompleteLocator: dc.WritePerMinute, MaxBuckets: dc.MaxBuckets})
		if err != nil {
			return nil, err
		}
		developerManagement = transport.NewDeveloperManagementService(developerusecase.NewManagement(repo, gate))
	}
	var sessionManagement *transport.SessionManagementService
	if sc := configuration.SessionManagement; sc != nil {
		if err := mongoadapter.EnsureSessionManagementSchema(ctx, database); err != nil {
			return nil, err
		}
		repo, err := mongoadapter.NewSessionManagementRepository(repository)
		if err != nil {
			return nil, err
		}
		gate, err := sessionmanagementrate.New(sc.GlobalPerMinute, sc.SourcePerMinute, sc.AccountPerMinute, sc.MaxBuckets)
		if err != nil {
			return nil, err
		}
		service, err := sessionmanagementusecase.New(repo, protocol, gate)
		if err != nil {
			return nil, err
		}
		sessionManagement = transport.NewSessionManagementService(service, gate)
	}
	var applicationUserStorage *transport.ApplicationUserStorageService
	if configuration.ApplicationUserStorage != nil {
		if err := mongoadapter.EnsureApplicationUserStorageSchema(ctx, database); err != nil {
			return nil, err
		}
		repo, err := mongoadapter.NewApplicationUserStorageRepository(repository)
		if err != nil {
			return nil, err
		}
		applicationUserStorage = transport.NewApplicationUserStorageService(applicationuserstorageusecase.New(repo))
	}
	return &transport.UserEndpoints{SessionManagement: sessionManagement, DeveloperManagement: developerManagement, AccountManagement: accountManagement, PlatformAdministrator: administrator, AcademicYearPolicy: academicYearPolicy,
		ApplicationOperations:         applicationOperations,
		CredentialManagement:          credentialRuntime.Service,
		PasswordManagement:            passwordManagement.Service,
		PasswordLogin:                 passwordManagement.Login,
		ApplicationUserStorage:        applicationUserStorage,
		DeveloperApplication:          developerApplication,
		EmailBinding:                  emailService,
		EmailAccount:                  emailAccount,
		EmailLogin:                    emailLoginService,
		CampusCertification:           campusCertification,
		Reviewer:                      transport.NewReviewerPermissionService(reviewerusecase.New(reviewerRepo)),
		IdentityIssuance:              issuance,
		Authentication:                authentication,
		Profile:                       transport.NewUserProfileServer(profileusecase.NewProfileService(profileRepo, profileCatalog, academicYearRepository)),
		ProfileIdentity:               transport.UserCapabilityIdentityMiddleware(profileIdentity),
		SessionIdentity:               transport.UserSessionMiddleware(login),
		MaxAuthenticationMessageBytes: c.Authentication.MaxMessageBytes,
	}, nil
}
