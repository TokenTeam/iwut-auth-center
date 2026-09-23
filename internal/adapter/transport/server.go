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

	authv1 "iwut-auth-center/api/gen/go/auth_center/v1/authentication"
	developerstatusv1 "iwut-auth-center/api/gen/go/auth_center/v1/developer_status"
	identityv1 "iwut-auth-center/api/gen/go/auth_center/v1/identity"
	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
	systemprincipalv1 "iwut-auth-center/api/gen/go/auth_center/v1/system_principal"
	profilev1 "iwut-auth-center/api/gen/go/auth_center/v1/user_profile"
	profiledomain "iwut-auth-center/internal/profile/domain"
)

type ServerConfig struct {
	HTTPAddr      string
	GRPCAddr      string
	UserEndpoints *UserEndpoints
}

// UserEndpoints is an optional, fully validated runtime assembled before listening.
type UserEndpoints struct {
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
			kgrpc.Options(grpc.ForceServerCodec(NewProfileStrictCodec()), grpc.MaxRecvMsgSize(max(profiledomain.MaxMessageBytes, endpoints.MaxAuthenticationMessageBytes))),
		)
	} else {
		options = append(options, kgrpc.Middleware(serviceIdentityMiddleware(verifier)))
	}
	server := kgrpc.NewServer(options...)
	if endpoints := configuration.UserEndpoints; endpoints != nil {
		authv1.RegisterAuthenticationServiceServer(server, endpoints.Authentication)
		profilev1.RegisterUserProfileServiceServer(server, endpoints.Profile)
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
		khttp.Filter(authHTTPFilter),
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
	if endpoints != nil {
		authv1.RegisterAuthenticationServiceHTTPServer(server, endpoints.Authentication)
		profilev1.RegisterUserProfileServiceHTTPServer(server, endpoints.Profile)
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
	case strings.HasPrefix(r.URL.Path, "/v1/registrations"):
		reason = "INVALID_REGISTRATION_INPUT"
	case r.URL.Path == "/v1/users/me/profile" || r.URL.Path == "/v1/user-profile-schema":
		reason = "INVALID_USER_PROFILE_EDIT"
	case r.URL.Path == "/v1/sessions/current":
		reason = ReasonInvalidSessionToken
	case strings.HasPrefix(r.URL.Path, "/v1/users/me/credentials/"):
		reason = "INVALID_CREDENTIAL_ID"
	}
	return kerrors.BadRequest(reason, "invalid request")
}

func oversizedHTTPInput(r *http.Request) error {
	reason := "AUTHENTICATION_INPUT_TOO_LARGE"
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
	case *authv1.UserRegistrationResult, *authv1.SessionEstablished:
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
	case "REGISTRATION_INPUT_TOO_LARGE", "AUTHENTICATION_INPUT_TOO_LARGE", profiledomain.ErrLimit.Error():
		converted.Code = http.StatusRequestEntityTooLarge
	case profiledomain.ErrExhausted.Error():
		converted.Code = http.StatusConflict
	case "CODEC":
		converted = kerrors.FromError(invalidHTTPInput(r))
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
