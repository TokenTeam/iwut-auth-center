package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	HTTPAddrEnv          = "AUTH_CENTER_HTTP_ADDR"
	GRPCAddrEnv          = "AUTH_CENTER_GRPC_ADDR"
	MongoURIEnv          = "AUTH_CENTER_MONGO_URI"
	MongoDatabaseEnv     = "AUTH_CENTER_MONGO_DATABASE"
	ServiceCallersEnv    = "AUTH_CENTER_SERVICE_CALLERS_B64"
	ServiceMaxTTLEnv     = "AUTH_CENTER_SERVICE_IDENTITY_MAX_TTL"
	ServiceClockSkewEnv  = "AUTH_CENTER_SERVICE_IDENTITY_CLOCK_SKEW"
	DefaultHTTPAddr      = ":8000"
	DefaultGRPCAddr      = ":9000"
	DefaultMongoURI      = "mongodb://127.0.0.1:27017"
	DefaultMongoDatabase = "iwut_auth_center"
	DefaultServiceMaxTTL = 2 * time.Minute
	DefaultServiceSkew   = 30 * time.Second
)

var ErrInvalidConfiguration = errors.New("invalid auth center configuration")

type LookupEnv func(key string) (value string, found bool)

type Config struct {
	OAuth                    *OAuth
	DeveloperApplication     *DeveloperApplication
	EmailBinding             *EmailBinding
	EmailLogin               *EmailBinding
	IdentityIssuance         *IdentityIssuance
	UserEndpoints            *UserEndpoints
	HTTPAddr                 string
	GRPCAddr                 string
	MongoURI                 string
	MongoDatabase            string
	ServiceCallers           []ServiceCallerRegistration
	ServiceIdentityMaxTTL    time.Duration
	ServiceIdentityClockSkew time.Duration
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
	if emailBinding != nil && emailLogin != nil && string(emailBinding.HMACKey) == string(emailLogin.HMACKey) {
		return Config{}, fmt.Errorf("%w: email login key must be independent", ErrInvalidConfiguration)
	}
	issuance, err := loadIdentityIssuance(lookup, userEndpoints, callers)
	if err != nil {
		return Config{}, err
	}
	developerApplication, err := loadDeveloperApplication(lookup, userEndpoints)
	if err != nil {
		return Config{}, err
	}
	oauth, err := loadOAuth(lookup)
	if err != nil {
		return Config{}, err
	}
	if oauth != nil && userEndpoints == nil {
		return Config{}, ErrInvalidConfiguration
	}
	return Config{
		OAuth:                oauth,
		DeveloperApplication: developerApplication,
		EmailBinding:         emailBinding,
		EmailLogin:           emailLogin,
		IdentityIssuance:     issuance,
		UserEndpoints:        userEndpoints,
		HTTPAddr:             httpAddress, GRPCAddr: address, MongoURI: mongoURI, MongoDatabase: database,
		ServiceCallers: callers, ServiceIdentityMaxTTL: maxTTL, ServiceIdentityClockSkew: clockSkew,
	}, nil
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
