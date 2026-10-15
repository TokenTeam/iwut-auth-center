package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	HTTPAddrEnv                 = "AUTH_CENTER_HTTP_ADDR"
	GRPCAddrEnv                 = "AUTH_CENTER_GRPC_ADDR"
	MongoURIEnv                 = "AUTH_CENTER_MONGO_URI"
	MongoDatabaseEnv            = "AUTH_CENTER_MONGO_DATABASE"
	ServiceCallersEnv           = "AUTH_CENTER_SERVICE_CALLERS_B64"
	ServiceMaxTTLEnv            = "AUTH_CENTER_SERVICE_IDENTITY_MAX_TTL"
	ServiceClockSkewEnv         = "AUTH_CENTER_SERVICE_IDENTITY_CLOCK_SKEW"
	LogLevelEnv                 = "AUTH_CENTER_LOG_LEVEL"
	OTLPGRPCEndpointEnv         = "AUTH_CENTER_OTLP_GRPC_ENDPOINT"
	OTLPInsecureEnv             = "AUTH_CENTER_OTLP_INSECURE"
	TraceSampleRatioEnv         = "AUTH_CENTER_TRACE_SAMPLE_RATIO"
	MetricExportIntervalEnv     = "AUTH_CENTER_METRIC_EXPORT_INTERVAL"
	DefaultHTTPAddr             = ":8000"
	DefaultGRPCAddr             = ":9000"
	DefaultMongoURI             = "mongodb://127.0.0.1:27017"
	DefaultMongoDatabase        = "iwut_auth_center"
	DefaultServiceMaxTTL        = 2 * time.Minute
	DefaultServiceSkew          = 30 * time.Second
	DefaultLogLevel             = "INFO"
	DefaultTraceSampleRatio     = 0.1
	DefaultMetricExportInterval = 30 * time.Second
)

var ErrInvalidConfiguration = errors.New("invalid auth center configuration")

type LookupEnv func(key string) (value string, found bool)

type Config struct {
	CredentialManagement            *CredentialManagement
	Password                        *Password
	ApplicationOperationsPermission *ApplicationOperationsPermission
	ApplicationClosure              *ApplicationClosure
	ApplicationCloseReauth          *ApplicationCloseReauth
	SessionManagement               *SessionManagement
	AccountClosure                  *AccountClosure
	DeveloperManagement             *DeveloperManagement
	OwnerExit                       *OwnerExit
	AccountManagement               *AccountManagement
	OAuth                           *OAuth
	PlatformAdministrator           *PlatformAdministrator
	AcademicYearPolicy              *AcademicYearPolicy
	ApplicationUserStorage          *ApplicationUserStorage
	DeveloperApplication            *DeveloperApplication
	EmailBinding                    *EmailBinding
	EmailLogin                      *EmailBinding
	CampusCertification             *EmailBinding
	IdentityIssuance                *IdentityIssuance
	UserEndpoints                   *UserEndpoints
	HTTPAddr                        string
	GRPCAddr                        string
	LogLevel                        string
	OTLPGRPCEndpoint                string
	OTLPInsecure                    bool
	TraceSampleRatio                float64
	MetricExportInterval            time.Duration
	MongoURI                        string
	MongoDatabase                   string
	ServiceCallers                  []ServiceCallerRegistration
	ServiceIdentityMaxTTL           time.Duration
	ServiceIdentityClockSkew        time.Duration
}

type ServiceCallerRegistration struct {
	IdentityAudiences       []string
	ServiceID               string
	Status                  string
	PublicKeyPEMByKID       map[string][]byte
	Permissions             []string
	SystemPrincipalPurposes []string
}

type serviceCallerJSON struct {
	IdentityAudiences       []string           `json:"identityAudiences"`
	Status                  string             `json:"status"`
	Keys                    map[string]keyJSON `json:"keys"`
	Permissions             []string           `json:"permissions"`
	SystemPrincipalPurposes []string           `json:"systemPrincipalPurposes"`
}

type keyJSON struct {
	PublicKeyPEMB64 string `json:"publicKeyPemB64"`
}

func LoadFromEnvironment() (Config, error) {
	return Load(os.LookupEnv)
}

func Load(lookup LookupEnv) (Config, error) {
	if lookup == nil {
		return Config{}, fmt.Errorf("%w: environment lookup is nil", ErrInvalidConfiguration)
	}
	address := DefaultGRPCAddr
	if raw, found := lookup(GRPCAddrEnv); found {
		address = strings.TrimSpace(raw)
		if address == "" {
			return Config{}, fmt.Errorf("%w: %s must not be empty when set", ErrInvalidConfiguration, GRPCAddrEnv)
		}
	}
	httpAddress := DefaultHTTPAddr
	if raw, found := lookup(HTTPAddrEnv); found {
		httpAddress = strings.TrimSpace(raw)
		if httpAddress == "" {
			return Config{}, fmt.Errorf("%w: %s must not be empty when set", ErrInvalidConfiguration, HTTPAddrEnv)
		}
	}
	logLevel := DefaultLogLevel
	if raw, found := lookup(LogLevelEnv); found {
		logLevel = strings.ToUpper(strings.TrimSpace(raw))
		switch logLevel {
		case "DEBUG", "INFO", "WARN", "ERROR":
		default:
			return Config{}, fmt.Errorf("%w: %s must be DEBUG, INFO, WARN or ERROR", ErrInvalidConfiguration, LogLevelEnv)
		}
	}
	otlpEndpoint := ""
	if raw, found := lookup(OTLPGRPCEndpointEnv); found {
		otlpEndpoint = strings.TrimSpace(raw)
		if !validHostPort(otlpEndpoint) {
			return Config{}, fmt.Errorf("%w: %s must be host:port with a numeric port from 1 through 65535", ErrInvalidConfiguration, OTLPGRPCEndpointEnv)
		}
	}
	otlpInsecure := false
	if raw, found := lookup(OTLPInsecureEnv); found {
		trimmed := strings.TrimSpace(raw)
		if trimmed != "true" && trimmed != "false" {
			return Config{}, fmt.Errorf("%w: %s must be true or false", ErrInvalidConfiguration, OTLPInsecureEnv)
		}
		otlpInsecure = trimmed == "true"
		if otlpEndpoint == "" {
			return Config{}, fmt.Errorf("%w: %s requires %s", ErrInvalidConfiguration, OTLPInsecureEnv, OTLPGRPCEndpointEnv)
		}
	}
	traceSampleRatio := DefaultTraceSampleRatio
	if raw, found := lookup(TraceSampleRatioEnv); found {
		parsed, parseErr := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if parseErr != nil || parsed < 0 || parsed > 1 {
			return Config{}, fmt.Errorf("%w: %s must be a number from 0 through 1", ErrInvalidConfiguration, TraceSampleRatioEnv)
		}
		traceSampleRatio = parsed
	}
	metricExportInterval := DefaultMetricExportInterval
	if raw, found := lookup(MetricExportIntervalEnv); found {
		parsed, parseErr := time.ParseDuration(strings.TrimSpace(raw))
		if parseErr != nil || parsed < time.Second {
			return Config{}, fmt.Errorf("%w: %s must be a Go duration of at least 1s", ErrInvalidConfiguration, MetricExportIntervalEnv)
		}
		metricExportInterval = parsed
	}
	mongoURI := DefaultMongoURI
	if raw, found := lookup(MongoURIEnv); found {
		mongoURI = strings.TrimSpace(raw)
		if mongoURI == "" {
			return Config{}, fmt.Errorf("%w: %s must not be empty when set", ErrInvalidConfiguration, MongoURIEnv)
		}
	}
	database := DefaultMongoDatabase
	if raw, found := lookup(MongoDatabaseEnv); found {
		database = strings.TrimSpace(raw)
		if database == "" {
			return Config{}, fmt.Errorf("%w: %s must not be empty when set", ErrInvalidConfiguration, MongoDatabaseEnv)
		}
	}
	rawCallers, found := lookup(ServiceCallersEnv)
	if !found || strings.TrimSpace(rawCallers) == "" {
		return Config{}, fmt.Errorf("%w: %s is required and must not be empty", ErrInvalidConfiguration, ServiceCallersEnv)
	}
	callers, err := parseServiceCallers(rawCallers)
	if err != nil {
		return Config{}, err
	}
	maxTTL := DefaultServiceMaxTTL
	if raw, found := lookup(ServiceMaxTTLEnv); found {
		maxTTL, err = time.ParseDuration(strings.TrimSpace(raw))
		if err != nil || maxTTL <= 0 {
			return Config{}, fmt.Errorf("%w: %s must be a positive Go duration", ErrInvalidConfiguration, ServiceMaxTTLEnv)
		}
	}
	clockSkew := DefaultServiceSkew
	if raw, found := lookup(ServiceClockSkewEnv); found {
		clockSkew, err = time.ParseDuration(strings.TrimSpace(raw))
		if err != nil || clockSkew < 0 {
			return Config{}, fmt.Errorf("%w: %s must be a non-negative Go duration", ErrInvalidConfiguration, ServiceClockSkewEnv)
		}
	}
	userEndpoints, err := loadUserEndpoints(lookup)
	if err != nil {
		return Config{}, err
	}
	emailBinding, err := loadEmailBinding(lookup, userEndpoints)
	if err != nil {
		return Config{}, err
	}
	emailLogin, err := loadEmailCapability(lookup, userEndpoints, "AUTH_EMAIL_LOGIN_ENABLED", "AUTH_EMAIL_LOGIN_CODE_KEY")
	if err != nil {
		return Config{}, err
	}
	password, err := loadPassword(lookup, userEndpoints, emailBinding, emailLogin)
	if err != nil {
		return Config{}, err
	}
	if emailBinding != nil && emailLogin != nil && string(emailBinding.HMACKey) == string(emailLogin.HMACKey) {
		return Config{}, fmt.Errorf("%w: email login key must be independent", ErrInvalidConfiguration)
	}
	campusCertification, err := loadCampusCertification(lookup, userEndpoints)
	if err != nil {
		return Config{}, err
	}
	if campusCertification != nil {
		if password == nil {
			return Config{}, fmt.Errorf("%w: campus alias requires password/email-account v3", ErrInvalidConfiguration)
		}
	}
	issuance, err := loadIdentityIssuance(lookup, userEndpoints, callers)
	if err != nil {
		return Config{}, err
	}
	applicationOperationsPermission, err := loadApplicationOperationsPermission(lookup, userEndpoints, issuance)
	if err != nil {
		return Config{}, err
	}
	applicationClosure, err := loadApplicationClosure(lookup, callers)
	if err != nil {
		return Config{}, err
	}
	applicationCloseReauth, err := loadApplicationCloseReauth(lookup, userEndpoints, issuance)
	if err != nil {
		return Config{}, err
	}
	developerApplication, err := loadDeveloperApplication(lookup, userEndpoints)
	if err != nil {
		return Config{}, err
	}
	platformAdministrator, err := loadPlatformAdministrator(lookup, userEndpoints)
	if err != nil {
		return Config{}, err
	}
	academicYearPolicy, err := loadAcademicYearPolicy(lookup, userEndpoints, issuance)
	if err != nil {
		return Config{}, err
	}
	accountManagement, err := loadAccountManagement(lookup, userEndpoints)
	if err != nil {
		return Config{}, err
	}
	developerManagement, err := loadDeveloperManagement(lookup, userEndpoints)
	if err != nil {
		return Config{}, err
	}
	sessionManagement, err := loadSessionManagement(lookup, userEndpoints)
	if err != nil {
		return Config{}, err
	}
	credentialManagement, err := loadCredentialManagement(lookup, userEndpoints, password)
	if err != nil {
		return Config{}, err
	}
	accountClosure, err := loadAccountClosure(lookup, userEndpoints)
	if err != nil {
		return Config{}, err
	}
	if err := validateDangerPasswordDependencies(password, accountClosure, applicationCloseReauth); err != nil {
		return Config{}, err
	}
	oauth, err := loadOAuth(lookup)
	if err != nil {
		return Config{}, err
	}
	if oauth != nil && userEndpoints == nil {
		return Config{}, ErrInvalidConfiguration
	}
	applicationUserStorage, err := loadApplicationUserStorage(lookup, oauth, userEndpoints)
	if err != nil {
		return Config{}, err
	}
	ownerExit, err := loadOwnerExit(lookup, userEndpoints, callers)
	if err != nil {
		return Config{}, err
	}
	return Config{
		CredentialManagement:            credentialManagement,
		ApplicationOperationsPermission: applicationOperationsPermission,
		ApplicationClosure:              applicationClosure,
		ApplicationCloseReauth:          applicationCloseReauth,
		SessionManagement:               sessionManagement,
		AccountClosure:                  accountClosure,
		DeveloperManagement:             developerManagement,
		OwnerExit:                       ownerExit,
		AccountManagement:               accountManagement,
		PlatformAdministrator:           platformAdministrator,
		AcademicYearPolicy:              academicYearPolicy,
		ApplicationUserStorage:          applicationUserStorage,
		OAuth:                           oauth,
		DeveloperApplication:            developerApplication,
		EmailBinding:                    emailBinding,
		Password:                        password,
		EmailLogin:                      emailLogin,
		CampusCertification:             campusCertification,
		IdentityIssuance:                issuance,
		UserEndpoints:                   userEndpoints,
		HTTPAddr:                        httpAddress, GRPCAddr: address, LogLevel: logLevel,
		OTLPGRPCEndpoint: otlpEndpoint, OTLPInsecure: otlpInsecure, TraceSampleRatio: traceSampleRatio, MetricExportInterval: metricExportInterval,
		MongoURI: mongoURI, MongoDatabase: database,
		ServiceCallers: callers, ServiceIdentityMaxTTL: maxTTL, ServiceIdentityClockSkew: clockSkew,
	}, nil
}

func validHostPort(raw string) bool {
	if raw == "" || strings.ContainsAny(raw, " \t\r\n/?#") {
		return false
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" || port == "" {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535
}

func parseServiceCallers(raw string) ([]ServiceCallerRegistration, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %s must be strict standard Base64", ErrInvalidConfiguration, ServiceCallersEnv)
	}
	var encoded map[string]serviceCallerJSON
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&encoded); err != nil {
		return nil, fmt.Errorf("%w: %s must decode to the caller registry JSON: %v", ErrInvalidConfiguration, ServiceCallersEnv, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: %s must contain exactly one JSON value", ErrInvalidConfiguration, ServiceCallersEnv)
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("%w: %s must declare at least one caller", ErrInvalidConfiguration, ServiceCallersEnv)
	}
	registrations := make([]ServiceCallerRegistration, 0, len(encoded))
	for serviceID, caller := range encoded {
		if serviceID == "" || strings.TrimSpace(serviceID) != serviceID {
			return nil, fmt.Errorf("%w: invalid service id %q", ErrInvalidConfiguration, serviceID)
		}
		if caller.Status != "ACTIVE" && caller.Status != "DISABLED" {
			return nil, fmt.Errorf("%w: caller %q has invalid status", ErrInvalidConfiguration, serviceID)
		}
		if len(caller.Keys) == 0 {
			return nil, fmt.Errorf("%w: caller %q must declare at least one key", ErrInvalidConfiguration, serviceID)
		}
		keys := make(map[string][]byte, len(caller.Keys))
		for kid, key := range caller.Keys {
			if kid == "" || strings.TrimSpace(kid) != kid || key.PublicKeyPEMB64 == "" {
				return nil, fmt.Errorf("%w: caller %q has an invalid key", ErrInvalidConfiguration, serviceID)
			}
			pemBytes, err := base64.StdEncoding.Strict().DecodeString(key.PublicKeyPEMB64)
			if err != nil || len(pemBytes) == 0 {
				return nil, fmt.Errorf("%w: caller %q key %q is not Base64 PEM", ErrInvalidConfiguration, serviceID, kid)
			}
			keys[kid] = pemBytes
		}
		permissions, err := uniqueNonEmpty(caller.Permissions)
		if err != nil {
			return nil, fmt.Errorf("%w: caller %q permissions: %v", ErrInvalidConfiguration, serviceID, err)
		}
		purposes, err := uniqueNonEmpty(caller.SystemPrincipalPurposes)
		if err != nil {
			return nil, fmt.Errorf("%w: caller %q system principal purposes: %v", ErrInvalidConfiguration, serviceID, err)
		}
		if err := validateIdentityAudiences(permissions, caller.IdentityAudiences); err != nil {
			return nil, err
		}
		registrations = append(registrations, ServiceCallerRegistration{
			IdentityAudiences: caller.IdentityAudiences,
			ServiceID:         serviceID, Status: caller.Status, PublicKeyPEMByKID: keys,
			Permissions: permissions, SystemPrincipalPurposes: purposes,
		})
	}
	return registrations, nil
}

func uniqueNonEmpty(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return nil, errors.New("contains an empty or whitespace-padded value")
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("contains duplicate %q", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}
