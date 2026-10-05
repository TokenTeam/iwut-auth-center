package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	kerrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	accountpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_management"
	ownerpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_owner_exit"
	authv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	developerapplicationpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_application"
	developermanagementpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_management"
	developerstatusv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_status"
	withdrawalpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_withdrawal"
	emailv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	emailloginv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_login"
	identityv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/identity"
	dp "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/oauth_delegation"
	gp "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/oauth_grant"
	adminpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/platform_administrator"
	reviewerpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/reviewer_permission"
	scopecatalogv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/scope_catalog"
	systemprincipalv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/system_principal"
	profilev1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	profiledomain "iwut-auth-center/internal/profile/domain"
)

type ServerConfig struct {
	OwnerExitDecision   *OwnerExitDecisionService
	DeveloperWithdrawal *DeveloperWithdrawalService
	OAuthGrant          *OAuthGrantService
	OAuthDelegation     *OAuthDelegationService
	OAuth               *OAuthHTTP
	HTTPAddr            string
	GRPCAddr            string
	UserEndpoints       *UserEndpoints
}

// UserEndpoints is an optional, fully validated runtime assembled before listening.
type UserEndpoints struct {
	DeveloperManagement           *DeveloperManagementService
	PlatformAdministrator         *PlatformAdministratorService
	AccountManagement             *AccountManagementService
	DeveloperApplication          *DeveloperApplicationService
	EmailBinding                  *EmailBindingService
	EmailLogin                    *EmailLoginService
	Reviewer                      *ReviewerPermissionService
	IdentityIssuance              *UserIdentityService
	Authentication                *AuthenticationService
	Profile                       *UserProfileServer
	ProfileIdentity               middleware.Middleware
	SessionIdentity               middleware.Middleware
	MaxAuthenticationMessageBytes int
}

// ServicePrefix belongs to Gateway routing, never to Proto HTTP annotations.
const ServicePrefix = "/auth-center"

type Servers struct {
	HTTP *khttp.Server
	GRPC *kgrpc.Server
}

// NewServers validates the shared runtime before assembling both transports.
func NewServers(
	configuration ServerConfig,
	verifier *ServiceIdentityVerifier,
	service *ScopeCatalogService,
	developerStatusService *DeveloperStatusService,
	systemPrincipalService *SystemPrincipalService,
) (*Servers, error) {
	if strings.TrimSpace(configuration.HTTPAddr) == "" {
		return nil, errors.New("HTTP address is required")
	}
	if configuration.GRPCAddr == "" {
		return nil, errors.New("gRPC address is required")
	}
	if service == nil {
		return nil, errors.New("scope catalog service is required")
	}
	if developerStatusService == nil {
		return nil, errors.New("developer status service is required")
	}
	if verifier == nil {
		return nil, errors.New("service identity verifier is required")
	}
	if systemPrincipalService == nil {
		return nil, errors.New("system principal service is required")
	}
	if endpoints := configuration.UserEndpoints; endpoints != nil {
		if endpoints.Authentication == nil || endpoints.Profile == nil || endpoints.ProfileIdentity == nil || endpoints.SessionIdentity == nil || endpoints.MaxAuthenticationMessageBytes <= 0 {
			return nil, errors.New("complete user endpoint runtime is required")
		}
	}

	return &Servers{
		HTTP: newHTTPServer(configuration, verifier),
		GRPC: newGRPCServer(configuration, verifier, service, developerStatusService, systemPrincipalService),
	}, nil
}

func newGRPCServer(
	configuration ServerConfig,
	verifier *ServiceIdentityVerifier,
	service *ScopeCatalogService,
	developerStatusService *DeveloperStatusService,
	systemPrincipalService *SystemPrincipalService,
) *kgrpc.Server {
	options := []kgrpc.ServerOption{kgrpc.Address(configuration.GRPCAddr)}
	if endpoints := configuration.UserEndpoints; endpoints != nil {
		options = append(options,
			kgrpc.Middleware(userEndpointAuthenticationMiddleware(verifier, endpoints.ProfileIdentity, endpoints.SessionIdentity, true, endpoints.MaxAuthenticationMessageBytes)),
			kgrpc.Options(grpc.ForceServerCodec(NewProfileStrictCodec(endpoints.MaxAuthenticationMessageBytes)), grpc.MaxRecvMsgSize(max(profiledomain.MaxMessageBytes, endpoints.MaxAuthenticationMessageBytes))),
		)
	} else {
		options = append(options, kgrpc.Middleware(userEndpointAuthenticationMiddleware(verifier, nil, nil, false)))
	}
	server := kgrpc.NewServer(options...)
	if configuration.OwnerExitDecision != nil {
		ownerpb.RegisterAccountOwnerExitDecisionServiceServer(server, configuration.OwnerExitDecision)
	}
	if configuration.DeveloperWithdrawal != nil {
		withdrawalpb.RegisterDeveloperWithdrawalServiceServer(server, configuration.DeveloperWithdrawal)
	}
	if configuration.OAuthGrant != nil {
		gp.RegisterOAuthGrantServiceServer(server, configuration.OAuthGrant)
	}
	if configuration.OAuthDelegation != nil {
		dp.RegisterOAuthDelegationServiceServer(server, configuration.OAuthDelegation)
	}
	emailService := NewEmailBindingService(nil)
	if endpoints := configuration.UserEndpoints; endpoints != nil && endpoints.EmailBinding != nil {
		emailService = endpoints.EmailBinding
	}
	emailv1.RegisterEmailBindingServiceServer(server, emailService)
	loginService := NewEmailLoginService(nil, 16*1024)
	if endpoints := configuration.UserEndpoints; endpoints != nil && endpoints.EmailLogin != nil {
		loginService = endpoints.EmailLogin
	}
	emailloginv1.RegisterEmailLoginServiceServer(server, loginService)
	if endpoints := configuration.UserEndpoints; endpoints != nil {
		if endpoints.DeveloperApplication != nil {
			developerapplicationpb.RegisterDeveloperApplicationServiceServer(server, endpoints.DeveloperApplication)
		}
		if endpoints.PlatformAdministrator != nil {
			adminpb.RegisterPlatformAdministratorServiceServer(server, endpoints.PlatformAdministrator)
		}
		if endpoints.AccountManagement != nil {
			accountpb.RegisterAccountManagementServiceServer(server, endpoints.AccountManagement)
		}
		if endpoints.DeveloperManagement != nil {
			developermanagementpb.RegisterDeveloperManagementServiceServer(server, endpoints.DeveloperManagement)
		}
		authv1.RegisterAuthenticationServiceServer(server, endpoints.Authentication)
		profilev1.RegisterUserProfileServiceServer(server, endpoints.Profile)
		if endpoints.Reviewer != nil {
			reviewerpb.RegisterReviewerPermissionServiceServer(server, endpoints.Reviewer)
		}
		if endpoints.IdentityIssuance != nil {
			identityv1.RegisterUserIdentityServiceServer(server, endpoints.IdentityIssuance)
		}
	}
	scopecatalogv1.RegisterScopeCatalogServer(server, service)
	developerstatusv1.RegisterDeveloperStatusDirectoryServer(server, developerStatusService)
	systemprincipalv1.RegisterSystemPrincipalDirectoryServer(server, systemPrincipalService)
	return server
}

// Only user entry points get HTTP bindings. Internal service methods (including
// Session-to-JWS issuance) deliberately have no HTTP registration.
func newHTTPServer(configuration ServerConfig, verifier *ServiceIdentityVerifier) *khttp.Server {
	options := []khttp.ServerOption{
		khttp.Address(configuration.HTTPAddr),
		khttp.Filter(func(next http.Handler) http.Handler {
			ordinary := authHTTPFilter(next)
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if configuration.OAuth != nil && configuration.OAuth.Handles(r) {
					configuration.OAuth.ServeHTTP(w, r)
					return
				}
				ordinary.ServeHTTP(w, r)
			})
		}),
		khttp.ResponseEncoder(authHTTPResponseEncoder),
		khttp.ErrorEncoder(authHTTPErrorEncoder),
	}
	endpoints := configuration.UserEndpoints
	if endpoints != nil {
		options = append(options,
			khttp.RequestDecoder(authHTTPDecoder(endpoints.MaxAuthenticationMessageBytes)),
			khttp.Middleware(userEndpointAuthenticationMiddleware(verifier, endpoints.ProfileIdentity, endpoints.SessionIdentity, true, endpoints.MaxAuthenticationMessageBytes)),
		)
	}
	server := khttp.NewServer(options...)
	if configuration.DeveloperWithdrawal != nil {
		withdrawalpb.RegisterDeveloperWithdrawalServiceHTTPServer(server, configuration.DeveloperWithdrawal)
	}
	if configuration.OAuthGrant != nil {
		gp.RegisterOAuthGrantServiceHTTPServer(server, configuration.OAuthGrant)
	}
	if endpoints != nil {
		if endpoints.EmailLogin != nil {
			emailloginv1.RegisterEmailLoginServiceHTTPServer(server, endpoints.EmailLogin)
		}
		if endpoints.EmailBinding != nil {
			emailv1.RegisterEmailBindingServiceHTTPServer(server, endpoints.EmailBinding)
		}
		if endpoints.DeveloperApplication != nil {
			developerapplicationpb.RegisterDeveloperApplicationServiceHTTPServer(server, endpoints.DeveloperApplication)
		}
		if endpoints.PlatformAdministrator != nil {
			adminpb.RegisterPlatformAdministratorServiceHTTPServer(server, endpoints.PlatformAdministrator)
		}
		if endpoints.AccountManagement != nil {
			accountpb.RegisterAccountManagementServiceHTTPServer(server, endpoints.AccountManagement)
		}
		if endpoints.DeveloperManagement != nil {
			developermanagementpb.RegisterDeveloperManagementServiceHTTPServer(server, endpoints.DeveloperManagement)
		}
		authv1.RegisterAuthenticationServiceHTTPServer(server, endpoints.Authentication)
		profilev1.RegisterUserProfileServiceHTTPServer(server, endpoints.Profile)
		if endpoints.Reviewer != nil {
			reviewerpb.RegisterReviewerPermissionServiceHTTPServer(server, endpoints.Reviewer)
		}
	}
	return server
}

// None of these commands accept query fields. Prevent generated query binding
// from overwriting JSON, and never allow credentials to be supplied in a URL.
func authHTTPFilter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			authHTTPErrorEncoder(w, r, invalidHTTPInput(r))
			return
		}
		if r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
			authHTTPErrorEncoder(w, r, kerrors.New(415, "UNSUPPORTED_CONTENT_ENCODING", "content encoding is unsupported"))
			return
		}
		// GET and DELETE have no request body, including chunked bodies.
		if r.Method == http.MethodGet || r.Method == http.MethodDelete {
			if r.Body != nil {
				data, err := io.ReadAll(io.LimitReader(r.Body, 1))
				if err != nil || len(data) != 0 {
					authHTTPErrorEncoder(w, r, invalidHTTPInput(r))
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func authHTTPDecoder(authenticationLimit int) khttp.DecodeRequestFunc {
	return func(r *http.Request, value any) error {
		limit := authenticationLimit
		switch value.(type) {
		case *developermanagementpb.ManageDeveloperStatusRequest, *developermanagementpb.GetManagedDeveloperStatusRequest:
			limit = min(limit, 16*1024)
		case *adminpb.ManagePlatformAdministratorRequest, *adminpb.GetPlatformAdministratorRequest, *adminpb.ListPlatformAdministratorsRequest:
			limit = min(limit, 16*1024)
		case *accountpb.ManageUserAccountStatusRequest, *accountpb.GetUserAccountStatusRequest:
			limit = 16 * 1024
		}
		if _, ok := value.(*profilev1.EditOwnProfileRequest); ok {
			limit = profiledomain.MaxMessageBytes
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return kerrors.New(415, "UNSUPPORTED_CONTENT_TYPE", "application/json is required")
		}
		if r.Body == nil {
			return invalidHTTPInput(r)
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
		if len(data) > limit {
			return oversizedHTTPInput(r)
		}
		if err != nil {
			return invalidHTTPInput(r)
		}
		if _, ok := value.(*profilev1.EditOwnProfileRequest); ok {
			if err := validateProfileJSON(data); err != nil {
				return err
			}
		}
		message, ok := value.(proto.Message)
		if !ok {
			return invalidHTTPInput(r)
		}
		// ProtoJSON rejects unknown fields, duplicate fields and conflicting oneof
		// branches. Do not use Kratos' permissive global JSON codec for input.
		if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, message); err != nil {
			return invalidHTTPInput(r)
		}
		return nil
	}
}

func invalidHTTPInput(r *http.Request) error {
	reason := "INVALID_LOGIN_INPUT"
	switch {
	case r.URL.Path == "/v1/developers:manage-status" || r.URL.Path == "/v1/developers:get-managed-status":
		reason = "INVALID_DEVELOPER_MANAGEMENT_REQUEST"
	case strings.HasPrefix(r.URL.Path, "/v1/users/me/developer-withdrawal:"):
		reason = "INVALID_DEVELOPER_WITHDRAWAL_REQUEST"
	case strings.HasPrefix(r.URL.Path, "/v1/platform-administrators:"):
		reason = "INVALID_PLATFORM_ADMIN_REQUEST"
	case strings.HasPrefix(r.URL.Path, "/v1/users/me/application-grants"):
		reason = "OAUTH_INVALID_REQUEST"
	case developerApplicationHTTPPath(r.URL.Path):
		reason = "INVALID_DEVELOPER_APPLICATION_REQUEST"
	case strings.HasPrefix(r.URL.Path, "/v1/email-logins"):
		reason = "INVALID_EMAIL_LOGIN_REQUEST"
	case emailHTTPPath(r.URL.Path):
		reason = "INVALID_EMAIL_REQUEST"
	case strings.HasSuffix(r.URL.Path, "/reviewer-permission"), strings.Contains(r.URL.Path, "/application-review-permissions"):
		reason = "INVALID_REVIEWER_PERMISSION_INPUT"
	case strings.HasPrefix(r.URL.Path, "/v1/registrations"):
		reason = "INVALID_REGISTRATION_INPUT"
	case r.URL.Path == "/v1/users/me/profile" || r.URL.Path == "/v1/user-profile-schema":
		reason = "INVALID_USER_PROFILE_EDIT"
	case r.URL.Path == "/v1/sessions/current":
		reason = ReasonInvalidSessionToken
	case strings.HasPrefix(r.URL.Path, "/v1/users/me/credentials/"):
		reason = "INVALID_CREDENTIAL_ID"
	}
	if r.URL.Path == "/v1/user-accounts:get-status" || r.URL.Path == "/v1/user-accounts:manage-status" {
		reason = "INVALID_ACCOUNT_STATUS_REQUEST"
	}
	return kerrors.BadRequest(reason, "invalid request")
}

func oversizedHTTPInput(r *http.Request) error {
	reason := "AUTHENTICATION_INPUT_TOO_LARGE"
	if strings.HasPrefix(r.URL.Path, "/v1/users/me/developer-withdrawal:") {
		reason = "DEVELOPER_WITHDRAWAL_REQUEST_TOO_LARGE"
	}
	if developerApplicationHTTPPath(r.URL.Path) {
		reason = "DEVELOPER_APPLICATION_REQUEST_TOO_LARGE"
	}
	if emailHTTPPath(r.URL.Path) {
		reason = "EMAIL_REQUEST_TOO_LARGE"
	}
	if strings.HasPrefix(r.URL.Path, "/v1/email-logins") {
		reason = "EMAIL_LOGIN_REQUEST_TOO_LARGE"
	}
	if strings.HasPrefix(r.URL.Path, "/v1/registrations") {
		reason = "REGISTRATION_INPUT_TOO_LARGE"
	}
	if r.URL.Path == "/v1/users/me/profile" {
		reason = profiledomain.ErrLimit.Error()
	}
	return kerrors.New(http.StatusRequestEntityTooLarge, reason, "request is too large")
}

func authHTTPResponseEncoder(w http.ResponseWriter, r *http.Request, value any) error {
	w.Header().Set("Cache-Control", "no-store")
	switch value.(type) {
	case *authv1.UserRegistrationResult, *authv1.SessionEstablished, *emailloginv1.EmailLoginResult:
		w.WriteHeader(http.StatusCreated)
	}
	return khttp.DefaultResponseEncoder(w, r, value)
}

func authHTTPErrorEncoder(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Cache-Control", "no-store")
	converted := kerrors.FromError(err)
	// RESOURCE_EXHAUSTED covers both rate limiting (429) and payload limits
	// (413); the UC's stable reason determines which HTTP status applies.
	switch converted.Reason {
	case "DEVELOPER_WITHDRAWAL_REQUEST_TOO_LARGE", "DEVELOPER_APPLICATION_REQUEST_TOO_LARGE", "EMAIL_LOGIN_REQUEST_TOO_LARGE", "EMAIL_REQUEST_TOO_LARGE", "REGISTRATION_INPUT_TOO_LARGE", "AUTHENTICATION_INPUT_TOO_LARGE", profiledomain.ErrLimit.Error():
		converted.Code = http.StatusRequestEntityTooLarge
	case "DEVELOPER_RESTORE_BLOCKED", "DEVELOPER_REVISION_EXHAUSTED", "ACCOUNT_REVISION_EXHAUSTED", "PLATFORM_ADMIN_GRANT_BLOCKED", "LAST_PLATFORM_ADMIN_REQUIRED", "PERMISSION_REVISION_EXHAUSTED":
		converted.Code = http.StatusConflict
	case "DEVELOPER_HANDLE_CHANGE_NOT_ALLOWED", "DEVELOPER_EMAIL_REQUIRED", "EMAIL_FLOW_MISMATCH", profiledomain.ErrExhausted.Error():
		converted.Code = http.StatusConflict
	case "CODEC":
		converted = kerrors.FromError(invalidHTTPInput(r))
	}
	if retry := converted.Metadata["retryAfterSeconds"]; retry != "" {
		w.Header().Set("Retry-After", retry)
	}
	khttp.DefaultErrorEncoder(w, r, converted)
}

// ProtoJSON ordinarily treats null lists/fields as absent. UC005 explicitly
// rejects null edit structure, so preserve that distinction before decoding.
func validateProfileJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return profileError(profiledomain.ErrInvalidEdit)
	}
	revision, ok := fields["expectedRevision"]
	if !ok {
		revision, ok = fields["expected_revision"]
	}
	if !ok {
		return profileError(profiledomain.ErrInvalidRevision)
	}
	var probe profilev1.EditOwnProfileRequest
	if (protojson.UnmarshalOptions{}).Unmarshal(append(append([]byte(`{"expectedRevision":`), revision...), '}'), &probe) != nil || probe.ExpectedRevision == nil || probe.GetExpectedRevision() <= 0 {
		return profileError(profiledomain.ErrInvalidRevision)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil || token == nil {
			return profileError(profiledomain.ErrInvalidEdit)
		}
	}
}

func emailHTTPPath(path string) bool {
	return path == "/v1/users/me/email-binding" || path == "/v1/email-bindings" || strings.HasPrefix(path, "/v1/email-bindings/")
}

func developerApplicationHTTPPath(path string) bool {
	return path == "/v1/users/me/developer-application" || path == "/v1/users/me/developer-eligibility"
}
